package es.in2.issuer.backend.shared.domain.service;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Validates client attestation JWTs per OAuth Attestation-Based Client Authentication.
 * Validates WIA (Wallet Instance Attestation) + PoP via HTTP headers.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ClientAttestationValidationService {

    public static final String HEADER_CLIENT_ATTESTATION = "OAuth-Client-Attestation";
    public static final String HEADER_CLIENT_ATTESTATION_POP = "OAuth-Client-Attestation-PoP";

    private static final long MAX_AGE_SECONDS = 300;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TrustedWalletProvidersService trustedWalletProvidersService;

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

            // Verify WIA signature
            verifyWiaSignature(wia);

            // Validate WIA expiration
            if (wiaClaims.getExpirationTime() != null) {
                if (Instant.now().isAfter(wiaClaims.getExpirationTime().toInstant())) {
                    throw new IllegalArgumentException("Client Attestation JWT has expired");
                }
            }

            // Validate WIA issuer against trusted wallet providers
            String wiaIssuer = wiaClaims.getIssuer();
            if (!trustedWalletProvidersService.isWalletProviderTrusted(wiaIssuer)) {
                throw new IllegalArgumentException("WIA issuer is not a trusted wallet provider: " + wiaIssuer);
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

            // Validate PoP freshness
            if (popClaims.getIssueTime() != null) {
                long iat = popClaims.getIssueTime().getTime() / 1000;
                long now = Instant.now().getEpochSecond();
                if (Math.abs(now - iat) > MAX_AGE_SECONDS) {
                    throw new IllegalArgumentException("PoP JWT expired (iat too old)");
                }
            }

            if (popClaims.getExpirationTime() != null) {
                if (Instant.now().isAfter(popClaims.getExpirationTime().toInstant())) {
                    throw new IllegalArgumentException("PoP JWT has expired");
                }
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

    private void verifyWiaSignature(SignedJWT wia) throws Exception {
        PublicKey wiaKey = null;

        // Try x5c certificate chain first
        List<Base64> x5c = wia.getHeader().getX509CertChain();
        if (x5c != null && !x5c.isEmpty()) {
            byte[] certBytes = x5c.getFirst().decode();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            wiaKey = cert.getPublicKey();
        }

        // Fallback to JWK in header
        if (wiaKey == null && wia.getHeader().getJWK() != null) {
            JWK headerJwk = wia.getHeader().getJWK();
            if (headerJwk instanceof AsymmetricJWK asymmetric) {
                wiaKey = asymmetric.toPublicKey();
            }
        }

        if (wiaKey == null) {
            throw new IllegalArgumentException("Cannot verify WIA signature: no x5c or jwk in header");
        }

        JWSVerifier wiaVerifier = new DefaultJWSVerifierFactory()
                .createJWSVerifier(wia.getHeader(), wiaKey);
        if (!wia.verify(wiaVerifier)) {
            throw new IllegalArgumentException("Client Attestation JWT signature verification failed");
        }
        log.debug("WIA signature verified");
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
