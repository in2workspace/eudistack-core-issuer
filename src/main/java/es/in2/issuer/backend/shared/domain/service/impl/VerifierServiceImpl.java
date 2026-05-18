package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.JWTVerificationException;
import es.in2.issuer.backend.shared.domain.exception.WellKnownInfoFetchException;
import es.in2.issuer.backend.shared.domain.model.dto.OpenIDProviderMetadata;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Date;

/**
 * Fetches verifier metadata and validates tokens signed by the verifier.
 *
 * <p><b>Iss validation</b> is delegated to the caller (see {@link VerifierService}).
 * This service assumes the token's {@code iss} has already been matched
 * exactly against {@code UrlResolver.expectedVerifierBaseUrl(exchange)}.
 *
 * <p>Internal URLs (well-known, JWKS) are composed via
 * {@link UriComponentsBuilder} to avoid the class of bugs where a path
 * starting with {@code /} concatenated to a base URL carrying a base-path
 * silently strips or duplicates the prefix.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class VerifierServiceImpl implements VerifierService {

    private final WebClient oauth2VerifierWebClient;
    private final UrlResolver urlResolver;

    // Lazily-initialized, cached JWK Set (populated on first use via Mono.cache())
    private volatile Mono<JWKSet> cachedJWKSet;

    @Override
    public Mono<Void> verifyToken(String accessToken) {
        return parseAndValidateJwt(accessToken, true)
                .doOnSuccess(unused -> log.info("The verification of the token is valid"))
                .onErrorResume(e -> {
                    log.error("Error while verifying token.", e);
                    return Mono.error(e);
                });
    }

    @Override
    public Mono<Void> verifyTokenWithoutExpiration(String accessToken) {
        return parseAndValidateJwt(accessToken, false)
                .doOnSuccess(unused -> log.info("The verification of the token without expiration is valid"))
                .onErrorResume(e -> {
                    log.error("Error while verifying token (without expiration)", e);
                    return Mono.error(e);
                });
    }

    private Mono<Void> parseAndValidateJwt(String accessToken, boolean checkExpiration) {
        return getWellKnownInfo()
                .flatMap(metadata -> fetchJWKSet(metadata.jwksUri()))
                .flatMap(jwkSet -> {
                    SignedJWT signedJWT;
                    JWTClaimsSet claims;

                    try {
                        signedJWT = SignedJWT.parse(accessToken);
                        claims = signedJWT.getJWTClaimsSet();
                    } catch (ParseException e) {
                        log.error("Error parsing JWT", e);
                        JWTParsingException jwtParsingException = new JWTParsingException("Error parsing JWT");
                        jwtParsingException.initCause(e);
                        return Mono.error(jwtParsingException);
                    }

                    // Iss is validated upstream by CustomAuthenticationManager
                    // via UrlResolver.expectedVerifierBaseUrl(exchange). We only
                    // check expiration (when requested) and signature here.

                    if (checkExpiration && (claims.getExpirationTime() == null
                            || new Date().after(claims.getExpirationTime()))) {
                        log.error("JWT validation failed: token has expired. expirationTime={}",
                                claims.getExpirationTime());

                        return Mono.error(new JWTVerificationException("Token has expired"));
                    }

                    try {
                        JWSVerifier verifier = getJWSVerifier(signedJWT, jwkSet);

                        if (!signedJWT.verify(verifier)) {
                            log.error("JWT validation failed: invalid token signature");
                            return Mono.error(new JWTVerificationException("Invalid token signature"));
                        }

                        return Mono.empty(); // Valid token
                    } catch (JOSEException e) {
                        log.error("Error verifying JWT signature.", e);
                        return Mono.error(new JWTVerificationException("Error verifying JWT signature"));
                    }
                });
    }

    private JWSVerifier getJWSVerifier(SignedJWT signedJWT, JWKSet jwkSet) throws JOSEException {
        String keyId = signedJWT.getHeader().getKeyID();
        JWK jwk = jwkSet.getKeyByKeyId(keyId);
        if (jwk == null) {
            throw new JOSEException("No matching JWK found for Key ID: " + keyId);
        }
        return switch (jwk.getKeyType().toString()) {
            case "RSA" -> new RSASSAVerifier(((RSAKey) jwk).toRSAPublicKey());
            case "EC" -> new ECDSAVerifier(((ECKey) jwk).toECPublicKey());
            case "oct" -> throw new JOSEException("Symmetric key type (oct) is not allowed for token verification");
            default -> throw new JOSEException("Unsupported JWK type: " + jwk.getKeyType());
        };
    }

    private Mono<JWKSet> fetchJWKSet(String jwksUri) {
        Mono<JWKSet> cached = cachedJWKSet;
        if (cached != null) {
            return cached;
        }
        // Rewrite public jwks_uri to hit the verifier over the intra-VPC
        // network. The rewrite preserves the public path (which already
        // carries the verifier base-path) and swaps only the origin —
        // UrlResolver implements this without duplicating the prefix.
        String internalJwksUri = urlResolver.rewriteToInternalVerifier(jwksUri);
        Mono<JWKSet> newCached = oauth2VerifierWebClient.get()
                .uri(internalJwksUri)
                .retrieve()
                .bodyToMono(String.class)
                .<JWKSet>handle((jwks, sink) -> {
                    try {
                        sink.next(JWKSet.parse(jwks));
                    } catch (ParseException e) {
                        sink.error(new JWTVerificationException("Error parsing the JWK Set"));
                    }
                })
                .onErrorMap(e -> !(e instanceof JWTVerificationException),
                        e -> new JWTVerificationException("Error fetching the JWK Set"))
                .cache();
        cachedJWKSet = newCached;
        return newCached;
    }

    @Override
    public Mono<OpenIDProviderMetadata> getWellKnownInfo() {
        // Compose with UriComponentsBuilder so the internal base URL's
        // base-path is preserved and the well-known path segments are
        // appended correctly — never concatenate a "/path" suffix with "+".
        String wellKnownInfoEndpoint = UriComponentsBuilder
                .fromUriString(urlResolver.internalVerifierBaseUrl())
                .pathSegment(".well-known", "openid-configuration")
                .build()
                .toUriString();

        return oauth2VerifierWebClient.get()
                .uri(wellKnownInfoEndpoint)
                .retrieve()
                .bodyToMono(OpenIDProviderMetadata.class)
                .onErrorMap(e -> new WellKnownInfoFetchException("Error fetching OpenID Provider Metadata", e));
    }
}