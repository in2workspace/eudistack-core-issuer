package es.in2.issuer.backend.shared.infrastructure.config.security;

import jakarta.annotation.Nullable;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationManager implements ReactiveAuthenticationManager {

    private final VerifierService verifierService;
    private final ObjectMapper objectMapper;
    private final AppConfig appConfig;
    private final JWTService jwtService;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final AuditService auditService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        log.debug("CustomAuthenticationManager - authenticate - start");
        final String accessToken = String.valueOf(authentication.getCredentials());
        final String maybeIdToken;
        final String requestBaseUrl;
        final String expectedVerifierBaseUrl;
        if (authentication instanceof es.in2.issuer.backend.shared.infrastructure.config.security.DualTokenAuthentication dta) {
            maybeIdToken = dta.getIdToken();
            requestBaseUrl = dta.getRequestBaseUrl();
            expectedVerifierBaseUrl = dta.getExpectedVerifierBaseUrl();
        } else {
            maybeIdToken = null;
            requestBaseUrl = null;
            expectedVerifierBaseUrl = null;
        }

        return extractIssuer(accessToken)
                .flatMap(issuer -> verifyAndParseJwtForIssuer(issuer, accessToken, requestBaseUrl, expectedVerifierBaseUrl))
                .flatMap(accessJwt -> getPrincipalName(accessJwt, maybeIdToken)
                        .map(principalName -> (Authentication) new JwtAuthenticationToken(
                                accessJwt,
                                Collections.emptyList(),
                                principalName
                        )))
                .doOnSuccess(auth -> auditService.auditSuccess("auth.success", auth.getName(),
                        null, null, Map.of()))
                .doOnError(e -> auditService.auditFailure("auth.failure", null,
                        e.getMessage(), Map.of()))
                .onErrorMap(e -> (e instanceof AuthenticationException)
                        ? e
                        : new AuthenticationServiceException(e.getMessage(), e));
    }

    // Returns the preferred principal: ID Token first; falls back to Access Token.
    private Mono<String> getPrincipalName(Jwt accessJwt, @Nullable String idToken) {
        log.debug("getPrincipalName - start");

        return getPrincipalFromIdToken(idToken)
                .switchIfEmpty(getPrincipalFromAccessToken(accessJwt))
                .doOnSuccess(p -> log.info("getPrincipalName - end with principal: {}", p));
    }

    private Mono<String> getPrincipalFromIdToken(@Nullable String idToken) {
        if (idToken == null) {
            log.debug("No ID Token provided");
            return Mono.empty();
        }

        log.debug("Resolving principal from ID Token");

        return parseAndValidateJwt(idToken, false)
                .map(validIdJwt -> {
                    String principal = jwtService.resolvePrincipal(validIdJwt);
                    return (principal == null || principal.isBlank()) ? null : principal;
                })
                .flatMap(Mono::justOrEmpty)
                .onErrorResume(ex -> {
                    log.warn("ID Token invalid or unreadable. Falling back to Access Token. Reason: {}", ex.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<String> getPrincipalFromAccessToken(Jwt accessJwt) {
        log.debug("Resolving principal from Access Token");
        return Mono.fromSupplier(() -> jwtService.resolvePrincipal(accessJwt));
    }



    private Mono<String> extractIssuer(String token) {
        return Mono.fromCallable(() -> {
                    try {
                        return SignedJWT.parse(token);
                    } catch (ParseException e) {
                        log.error("Failed to parse JWT", e);
                        throw new BadCredentialsException("Invalid JWT token format", e);
                    }
                })
                .flatMap(signedJWT -> {
                    try {
                        String issuer = signedJWT.getJWTClaimsSet().getIssuer();
                        log.debug("CustomAuthenticationManager - Issuer - {}", issuer);

                        if (issuer == null) {
                            log.error("Missing issuer (iss) claim");
                            return Mono.error(new BadCredentialsException("Missing issuer (iss) claim"));
                        }
                        return Mono.just(issuer);

                    } catch (ParseException e) {
                        return Mono.error(e);
                    }
                })
                .onErrorMap(ParseException.class, e -> {
                    log.error("Unable to parse JWT claims", e);
                    return new BadCredentialsException("Unable to parse JWT claims", e);
                });
    }

    private Mono<Jwt> verifyAndParseJwtForIssuer(
            String issuer,
            String token,
            @Nullable String requestBaseUrl,
            @Nullable String expectedVerifierBaseUrl
    ) {
        // Preferred path (HAIP-compliant): issuer-backend token, exact match
        // against the public base URL derived from the live request.
        if (requestBaseUrl != null && issuer.equals(requestBaseUrl)) {
            log.debug("Token from Credential Issuer (exact match with request base URL) - {}", issuer);
            return handleIssuerBackendToken(token);
        }
        // Preferred path for verifier tokens under same-origin routing: the
        // verifier lives at ${origin}/verifier and signs tokens with that iss.
        // Matching exactly lets us accept the token without APP_VERIFIER_URL.
        if (expectedVerifierBaseUrl != null && issuer.equals(expectedVerifierBaseUrl)) {
            log.debug("Token from Verifier (exact match with request origin) - {}", issuer);
            return handleVerifierToken(token, true);
        }
        // Fallback path: APP_URL-based fuzzy match. Kept for contexts where the
        // request base URL is not available (internal M2M paths, tests) and for
        // backwards compatibility. baseOriginMatches is intentionally fuzzy and
        // would also match verifier URLs on the same domain (e.g. issuer.cgcom.*
        // vs verifier.cgcom.*) — hence the verifier check is second.
        if (appConfig.isIssuerBackendIssuer(issuer)) {
            log.debug("Token from Credential Issuer (APP_URL fallback) - {}", issuer);
            return handleIssuerBackendToken(token);
        }
        if (appConfig.isVerifierIssuer(issuer)) {
            log.debug("Token from Verifier (APP_VERIFIER_URL fallback) - issuer: {}", issuer);
            return handleVerifierToken(token, false);
        }
        log.debug("Token from unknown issuer");
        return Mono.error(new BadCredentialsException("Unknown token issuer: " + issuer));
    }

    private Mono<Jwt> handleVerifierToken(String token, boolean issuerAlreadyMatched) {
        Mono<Void> verification = issuerAlreadyMatched
                ? verifierService.verifyTokenSkippingIssuerCheck(token)
                : verifierService.verifyToken(token);
        return verification.then(parseAndValidateJwt(token, Boolean.FALSE));
    }

    private Mono<Jwt> handleIssuerBackendToken(String token) {
        return Mono.fromCallable(() -> SignedJWT.parse(token))
                .flatMap(jwtService::validateJwtSignatureReactive)
                .flatMap(isValid -> {
                    if (!Boolean.TRUE.equals(isValid)) {
                        log.error("Invalid JWT signature");
                        return Mono.error(new BadCredentialsException("Invalid JWT signature"));
                    }
                    return parseAndValidateJwt(token, Boolean.FALSE);
                })
                .onErrorMap(ParseException.class, e -> {
                    log.error("Failed to parse JWS", e);
                    return new BadCredentialsException("Invalid JWS token format", e);
                });
    }

    private Mono<Jwt> parseAndValidateJwt(String token, boolean shouldValidateCredentialType) {
        return Mono.fromCallable(() -> {
            log.debug("parseAndValidateJwt");
            String[] parts = token.split("\\.");
            if (parts.length < 3) {
                throw new BadCredentialsException("Invalid JWT token format");
            }

            // Decode and parse headers
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            Map<String, Object> headers = objectMapper.readValue(headerJson, Map.class);

            // Decode and parse payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            Map<String, Object> claims = objectMapper.readValue(payloadJson, Map.class);

            // Validate credential_type claim
            if (shouldValidateCredentialType) validateCredentialType(claims);

            // Extract issuedAt and expiresAt times if present
            Instant issuedAt = claims.containsKey("iat") ? Instant.ofEpochSecond(((Number) claims.get("iat")).longValue()) : Instant.now();
            Instant expiresAt = claims.containsKey("exp") ? Instant.ofEpochSecond(((Number) claims.get("exp")).longValue()) : Instant.now().plusSeconds(3600);

            return new Jwt(token, issuedAt, expiresAt, headers, claims);
        });
    }

    private Set<String> getAcceptedVcTypes() {
        return credentialProfileRegistry.getAllProfiles().values().stream()
                .map(es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile::credentialType)
                .collect(java.util.stream.Collectors.toSet());
    }

    private void validateCredentialType(Map<String, Object> claims) {
        Object credentialType = claims.get("credential_type");
        log.debug("validateCredentialType");
        if (credentialType == null) {
            log.error("The 'credential_type' claim is required but not present.");
            throw new BadCredentialsException("The 'credential_type' claim is required but not present.");
        }
        String typeStr = credentialType.toString();
        Set<String> acceptedTypes = getAcceptedVcTypes();
        if (!acceptedTypes.contains(typeStr)) {
            log.error("Credential type '{}' not accepted. Accepted: {}", typeStr, acceptedTypes);
            throw new BadCredentialsException("Credential type required: one of " + acceptedTypes);
        }
    }

}
