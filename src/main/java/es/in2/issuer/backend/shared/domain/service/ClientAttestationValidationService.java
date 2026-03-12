package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Validates client attestation JWTs per OAuth Attestation-Based Client Authentication.
 * Validates WIA (Wallet Instance Attestation) + PoP via HTTP headers.
 */
@Slf4j
@Service
public class ClientAttestationValidationService {

    public static final String HEADER_CLIENT_ATTESTATION = "OAuth-Client-Attestation";
    public static final String HEADER_CLIENT_ATTESTATION_POP = "OAuth-Client-Attestation-PoP";

    private static final long MAX_AGE_SECONDS = 300;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TrustedWalletProvidersService trustedWalletProvidersService;
    private final String issuerUrl;

    // SEC-19: PoP jti replay detection cache
    private final Cache<String, Boolean> usedPopJtis = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofSeconds(MAX_AGE_SECONDS))
            .maximumSize(100_000)
            .build();

    public ClientAttestationValidationService(
            TrustedWalletProvidersService trustedWalletProvidersService,
            @Value("${app.url:}") String issuerUrl) {
        this.trustedWalletProvidersService = trustedWalletProvidersService;
        this.issuerUrl = issuerUrl;
    }

    /**
     * Validate WIA + PoP headers and return the extracted client_id.
     */
    public String validateHeaders(String wiaJwt, String popJwt) {
        if (wiaJwt == null || wiaJwt.isBlank()) {
            throw new IllegalArgumentException("Missing " + HEADER_CLIENT_ATTESTATION + " header");
        }
        if (popJwt == null || popJwt.isBlank()) {
            throw new IllegalArgumentException("Missing " + HEADER_CLIENT_ATTESTATION_POP + " header");
        }

        return validateWiaAndPop(wiaJwt, popJwt);
    }

    private String validateWiaAndPop(String wiaJwtString, String popJwtString) {
        try {
            // Parse WIA
            SignedJWT wia = SignedJWT.parse(wiaJwtString);
            JWTClaimsSet wiaClaims = wia.getJWTClaimsSet();
            log.debug("WIA parsed: alg={}, typ={}, sub={}, iss={}",
                    wia.getHeader().getAlgorithm(), wia.getHeader().getType(),
                    wiaClaims.getSubject(), wiaClaims.getIssuer());

            // Validate WIA issuer against trusted wallet providers
            String wiaIssuer = wiaClaims.getIssuer();
            if (!trustedWalletProvidersService.isWalletProviderTrusted(wiaIssuer)) {
                throw new IllegalArgumentException("WIA issuer is not a trusted wallet provider: " + wiaIssuer);
            }

            // SEC-09: Verify WIA signature against trusted provider's publicKeyPem (if configured),
            // not against the key embedded in the WIA itself
            verifyWiaSignature(wia, wiaIssuer);

            // Validate WIA expiration
            if (wiaClaims.getExpirationTime() != null) {
                if (Instant.now().isAfter(wiaClaims.getExpirationTime().toInstant())) {
                    throw new IllegalArgumentException("Client Attestation JWT has expired");
                }
            }

            // Extract client_id from sub
            String clientId = wiaClaims.getSubject();

            // Parse PoP
            SignedJWT pop = SignedJWT.parse(popJwtString);
            JWTClaimsSet popClaims = pop.getJWTClaimsSet();

            // Extract cnf key from WIA for PoP verification
            JWK cnfKey = extractCnfKey(wiaClaims);
            if (cnfKey == null) {
                cnfKey = extractKeyViaJkt(wiaClaims, pop);
            }
            if (cnfKey == null) {
                throw new IllegalArgumentException("WIA missing cnf key for PoP verification");
            }

            // Verify PoP signature
            if (!(cnfKey instanceof AsymmetricJWK asymmetricKey)) {
                throw new IllegalArgumentException("cnf key must be an asymmetric key");
            }
            PublicKey publicKey = asymmetricKey.toPublicKey();
            JWSVerifier verifier = new DefaultJWSVerifierFactory()
                    .createJWSVerifier(pop.getHeader(), publicKey);
            if (!pop.verify(verifier)) {
                throw new IllegalArgumentException("PoP signature verification failed");
            }

            // SEC-19: Validate PoP iat (mandatory)
            if (popClaims.getIssueTime() == null) {
                throw new IllegalArgumentException("PoP JWT missing mandatory iat claim");
            }
            long iat = popClaims.getIssueTime().getTime() / 1000;
            long now = Instant.now().getEpochSecond();
            if (Math.abs(now - iat) > MAX_AGE_SECONDS) {
                throw new IllegalArgumentException("PoP JWT expired (iat too old)");
            }

            if (popClaims.getExpirationTime() != null) {
                if (Instant.now().isAfter(popClaims.getExpirationTime().toInstant())) {
                    throw new IllegalArgumentException("PoP JWT has expired");
                }
            }

            // SEC-19: Validate PoP aud (must match this issuer)
            List<String> audience = popClaims.getAudience();
            if (issuerUrl != null && !issuerUrl.isBlank() && (audience == null || !audience.contains(issuerUrl))) {
                throw new IllegalArgumentException("PoP JWT aud does not match this issuer");
            }

            // SEC-19: PoP jti replay detection
            String popJti = popClaims.getJWTID();
            if (popJti != null) {
                if (usedPopJtis.getIfPresent(popJti) != null) {
                    throw new IllegalArgumentException("PoP jti replay detected");
                }
                usedPopJtis.put(popJti, Boolean.TRUE);
            }

            log.info("Client attestation validated: client_id={}, wia_iss={}", clientId, wiaIssuer);
            return clientId;

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Client attestation validation failed: {}", e.getMessage(), e);
            throw new IllegalArgumentException("Invalid client attestation: " + e.getMessage(), e);
        }
    }

    private void verifyWiaSignature(SignedJWT wia, String wiaIssuer) throws Exception {
        PublicKey wiaKey = null;

        // SEC-09: Try trusted provider's configured publicKeyPem first
        var providers = trustedWalletProvidersService.getAllTrustedProviders();
        for (var provider : providers) {
            if (provider.id().equals(wiaIssuer) && provider.publicKeyPem() != null && !provider.publicKeyPem().isBlank()) {
                wiaKey = parsePemPublicKey(provider.publicKeyPem());
                log.debug("WIA signature will be verified against trusted provider's configured key for: {}", wiaIssuer);
                break;
            }
        }

        // Fallback: try x5c certificate chain
        if (wiaKey == null) {
            List<Base64> x5c = wia.getHeader().getX509CertChain();
            if (x5c != null && !x5c.isEmpty()) {
                byte[] certBytes = x5c.getFirst().decode();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                wiaKey = cert.getPublicKey();
            }
        }

        // Last fallback: JWK in header (least secure — self-signed)
        if (wiaKey == null && wia.getHeader().getJWK() != null) {
            JWK headerJwk = wia.getHeader().getJWK();
            if (headerJwk instanceof AsymmetricJWK asymmetric) {
                wiaKey = asymmetric.toPublicKey();
                log.warn("WIA verified with self-signed key from header for issuer: {}. "
                        + "Configure publicKeyPem in trusted-wallet-providers.yaml for production.", wiaIssuer);
            }
        }

        if (wiaKey == null) {
            throw new IllegalArgumentException("Cannot verify WIA signature: no trusted key, x5c or jwk available");
        }

        JWSVerifier wiaVerifier = new DefaultJWSVerifierFactory()
                .createJWSVerifier(wia.getHeader(), wiaKey);
        if (!wia.verify(wiaVerifier)) {
            throw new IllegalArgumentException("Client Attestation JWT signature verification failed");
        }
        log.debug("WIA signature verified");
    }

    private PublicKey parsePemPublicKey(String pem) throws Exception {
        String stripped = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = java.util.Base64.getDecoder().decode(stripped);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        // Try EC first (most common for EUDI), fallback to RSA
        try {
            return KeyFactory.getInstance("EC").generatePublic(keySpec);
        } catch (Exception e) {
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        }
    }

    @SuppressWarnings("unchecked")
    private JWK extractCnfKey(JWTClaimsSet wiaClaims) {
        try {
            var cnf = wiaClaims.getJSONObjectClaim("cnf");
            if (cnf == null) return null;
            var jwkMap = (Map<String, Object>) cnf.get("jwk");
            if (jwkMap == null) return null;
            String jwkJson = MAPPER.writeValueAsString(jwkMap);
            return JWK.parse(jwkJson);
        } catch (Exception e) {
            log.warn("Could not extract cnf key from WIA: {}", e.getMessage());
            return null;
        }
    }

    private JWK extractKeyViaJkt(JWTClaimsSet wiaClaims, SignedJWT pop) {
        try {
            var cnf = wiaClaims.getJSONObjectClaim("cnf");
            if (cnf == null) return null;
            String jkt = (String) cnf.get("jkt");
            if (jkt == null) return null;

            JWK popHeaderKey = pop.getHeader().getJWK();
            if (popHeaderKey == null) return null;

            String thumbprint = popHeaderKey.computeThumbprint().toString();
            if (!jkt.equals(thumbprint)) {
                throw new IllegalArgumentException("PoP key thumbprint does not match WIA cnf.jkt");
            }
            return popHeaderKey.toPublicJWK();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Could not extract key via jkt: {}", e.getMessage());
            return null;
        }
    }
}
