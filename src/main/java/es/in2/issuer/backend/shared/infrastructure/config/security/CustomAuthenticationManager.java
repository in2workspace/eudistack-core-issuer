package es.in2.issuer.backend.shared.infrastructure.config.security;

import jakarta.annotation.Nullable;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
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
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * Authenticates JWT access tokens (and optional ID tokens) coming through
 * the {@link AuthenticationWebFilter} pipeline.
 *
 * <p>Validation of the {@code iss} claim is <b>strictly</b> an exact match
 * against URLs derived from the live {@link ServerWebExchange} via
 * {@link UrlResolver}: either the issuer's own public base URL or the
 * verifier's expected same-origin URL. No APP_URL fallback — if there is
 * no exchange, the token is rejected.
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationManager implements ReactiveAuthenticationManager {

    private final VerifierService verifierService;
    private final ObjectMapper objectMapper;
    private final JWTService jwtService;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final AuditService auditService;
    private final UrlResolver urlResolver;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        log.debug("CustomAuthenticationManager - authenticate - start");
        final String accessToken = String.valueOf(authentication.getCredentials());
        final String maybeIdToken;
        final ServerWebExchange exchange;
        if (authentication instanceof DualTokenAuthentication dta) {
            maybeIdToken = dta.getIdToken();
            exchange = dta.getRequestExchange();
        } else {
            maybeIdToken = null;
            exchange = null;
        }

        return extractIssuer(accessToken)
                .flatMap(issuer -> verifyTokenByIssuer(issuer, accessToken, exchange))
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
        return parseJwt(idToken)
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

    private Mono<Jwt> verifyTokenByIssuer(String issuer, String token, @Nullable ServerWebExchange exchange) {
        if (exchange == null) {
            log.warn("Authentication attempted without a request exchange; rejecting token");
            return Mono.error(new BadCredentialsException("Request context unavailable"));
        }
        String expectedIssuer = urlResolver.publicIssuerBaseUrl(exchange);
        if (expectedIssuer.equals(issuer)) {
            log.debug("Token from Credential Issuer (exact match) - {}", issuer);
            return handleIssuerBackendToken(token);
        }
        String expectedVerifier = urlResolver.expectedVerifierBaseUrl(exchange);
        if (expectedVerifier.equals(issuer)) {
            log.debug("Token from Verifier (exact match) - {}", issuer);
            return handleVerifierToken(token);
        }
        log.debug("Token from unknown issuer: iss={}, expectedIssuer={}, expectedVerifier={}",
                issuer, expectedIssuer, expectedVerifier);
        return Mono.error(new BadCredentialsException("Unknown token issuer: " + issuer));
    }

    private Mono<Jwt> handleVerifierToken(String token) {
        // The caller has already matched iss exactly against the expected
        // verifier URL, so VerifierService skips its own iss check and
        // validates only signature + expiration.
        return verifierService.verifyToken(token).then(parseJwt(token));
    }

    private Mono<Jwt> handleIssuerBackendToken(String token) {
        return Mono.fromCallable(() -> SignedJWT.parse(token))
                .flatMap(jwtService::validateJwtSignatureReactive)
                .flatMap(isValid -> {
                    if (!Boolean.TRUE.equals(isValid)) {
                        log.error("Invalid JWT signature");
                        return Mono.error(new BadCredentialsException("Invalid JWT signature"));
                    }
                    return parseJwt(token);
                })
                .onErrorMap(ParseException.class, e -> {
                    log.error("Failed to parse JWS", e);
                    return new BadCredentialsException("Invalid JWS token format", e);
                });
    }

    @SuppressWarnings("unchecked")
    private Mono<Jwt> parseJwt(String token) {
        return Mono.fromCallable(() -> {
            log.debug("parseJwt");
            String[] parts = token.split("\\.");
            if (parts.length < 3) {
                throw new BadCredentialsException("Invalid JWT token format");
            }
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            Map<String, Object> headers = objectMapper.readValue(headerJson, Map.class);
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            Map<String, Object> claims = objectMapper.readValue(payloadJson, Map.class);
            Instant issuedAt = claims.containsKey("iat") ? Instant.ofEpochSecond(((Number) claims.get("iat")).longValue()) : Instant.now();
            Instant expiresAt = claims.containsKey("exp") ? Instant.ofEpochSecond(((Number) claims.get("exp")).longValue()) : Instant.now().plusSeconds(3600);
            return new Jwt(token, issuedAt, expiresAt, headers, claims);
        });
    }

    // Reserved for controllers that need to validate credential_type server-side.
    // Kept private to avoid misuse from other callers.
    @SuppressWarnings("unused")
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

    private Set<String> getAcceptedVcTypes() {
        return credentialProfileRegistry.getAllProfiles().values().stream()
                .map(es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile::credentialType)
                .collect(java.util.stream.Collectors.toSet());
    }
}
