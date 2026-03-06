package es.in2.issuer.backend.shared.domain.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * DPoP proof validation per RFC 9449.
 */
@Slf4j
@Service
public class DpopValidationService {

    private static final long MAX_AGE_SECONDS = 300;

    // SEC-03: Replace unbounded ConcurrentHashMap with Caffeine cache (TTL + max size)
    private final Cache<String, Boolean> usedJtis = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofSeconds(MAX_AGE_SECONDS))
            .maximumSize(100_000)
            .build();

    /**
     * Validate a DPoP proof JWT and return the public key thumbprint (jkt).
     *
     * @param dpopHeader the DPoP header value
     * @param httpMethod expected HTTP method
     * @param httpUri    expected HTTP URI
     * @return the JWK thumbprint (SHA-256) of the DPoP key for cnf binding
     */
    public String validate(String dpopHeader, String httpMethod, String httpUri) {
        return validate(dpopHeader, httpMethod, httpUri, null);
    }

    /**
     * Validate a DPoP proof JWT, optionally bound to an access token.
     *
     * @param dpopHeader  the DPoP header value
     * @param httpMethod  expected HTTP method
     * @param httpUri     expected HTTP URI
     * @param accessToken the access token to verify the ath claim against (nullable for token endpoint)
     * @return the JWK thumbprint (SHA-256) of the DPoP key for cnf binding
     */
    public String validate(String dpopHeader, String httpMethod, String httpUri, String accessToken) {
        if (dpopHeader == null || dpopHeader.isBlank()) {
            throw new IllegalArgumentException("Missing DPoP proof");
        }

        try {
            SignedJWT dpop = SignedJWT.parse(dpopHeader);
            JWSHeader header = dpop.getHeader();

            // Must be typ: dpop+jwt
            if (header.getType() == null || !"dpop+jwt".equals(header.getType().getType())) {
                throw new IllegalArgumentException("DPoP typ must be dpop+jwt");
            }

            // Must have jwk in header
            JWK headerJwk = header.getJWK();
            if (headerJwk == null) {
                throw new IllegalArgumentException("DPoP must contain jwk header");
            }

            // Must be ES256
            if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
                throw new IllegalArgumentException("DPoP must use ES256");
            }

            ECKey publicKey = ECKey.parse(headerJwk.toJSONObject());
            if (publicKey.isPrivate()) {
                throw new IllegalArgumentException("DPoP jwk must be public key only");
            }

            // Verify signature
            if (!dpop.verify(new ECDSAVerifier(publicKey))) {
                throw new IllegalArgumentException("DPoP signature invalid");
            }

            JWTClaimsSet claims = dpop.getJWTClaimsSet();

            // Validate htm
            if (!httpMethod.equalsIgnoreCase(claims.getStringClaim("htm"))) {
                throw new IllegalArgumentException("DPoP htm mismatch");
            }

            // Validate htu
            if (!httpUri.equals(claims.getStringClaim("htu"))) {
                throw new IllegalArgumentException("DPoP htu mismatch");
            }

            // Validate iat freshness
            if (claims.getIssueTime() == null) {
                throw new IllegalArgumentException("DPoP missing iat claim");
            }
            long iat = claims.getIssueTime().getTime() / 1000;
            long now = Instant.now().getEpochSecond();
            if (Math.abs(now - iat) > MAX_AGE_SECONDS) {
                throw new IllegalArgumentException("DPoP proof expired");
            }

            // Validate jti uniqueness
            String jti = claims.getJWTID();
            if (jti == null || usedJtis.getIfPresent(jti) != null) {
                throw new IllegalArgumentException("DPoP jti replay detected");
            }
            usedJtis.put(jti, Boolean.TRUE);

            // SEC-22: Validate ath (access token hash) when an access token is bound
            if (accessToken != null) {
                String athClaim = claims.getStringClaim("ath");
                if (athClaim == null) {
                    throw new IllegalArgumentException("DPoP missing ath claim for token-bound proof");
                }
                String expectedAth = computeAth(accessToken);
                if (!expectedAth.equals(athClaim)) {
                    throw new IllegalArgumentException("DPoP ath mismatch");
                }
            }

            // Return the JWK thumbprint for cnf.jkt binding
            String thumbprint = publicKey.computeThumbprint().toString();
            log.debug("DPoP proof validated, jkt={}", thumbprint);
            return thumbprint;

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid DPoP proof: " + e.getMessage(), e);
        }
    }

    /**
     * Compute the access token hash per RFC 9449 §4.2:
     * base64url(SHA-256(ASCII(access_token)))
     */
    private String computeAth(String accessToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to compute ath: " + e.getMessage(), e);
        }
    }
}