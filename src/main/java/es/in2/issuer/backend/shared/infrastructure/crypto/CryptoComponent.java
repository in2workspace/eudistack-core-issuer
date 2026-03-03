package es.in2.issuer.backend.shared.infrastructure.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import es.in2.issuer.backend.shared.domain.exception.ECKeyCreationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * Provides the Authorization Server's EC P-256 key used exclusively for signing
 * OAuth2 tokens (access tokens, client assertions, etc.).
 * <p>
 * The key ID (kid) is a JWK Thumbprint (RFC 7638, SHA-256, base64url),
 * which can be resolved via the {@code jwks_uri} endpoint.
 * <p>
 * Credential signing uses a separate certificate-backed key via SigningProvider SPI.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class CryptoComponent {

    private final CryptoConfig cryptoConfig;

    @Bean
    public ECKey getECKey() {
        String privateKeyHex = cryptoConfig.getPrivateKey();
        if (privateKeyHex == null || privateKeyHex.isBlank()) {
            log.info("No AS private key configured — generating ephemeral EC P-256 keypair for token signing.");
            return generateEphemeralEcKey();
        }
        return buildEcKeyFromPrivateKey(privateKeyHex);
    }

    private ECKey buildEcKeyFromPrivateKey(String privateKeyHex) {
        try {
            BigInteger privateKeyInt = new BigInteger(privateKeyHex, 16);

            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());

            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInt, ecSpec);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecSpec.getG().multiply(privateKeyInt), ecSpec);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

            return buildWithThumbprintKid(publicKey, privateKey);
        } catch (Exception e) {
            throw new ECKeyCreationException("Error creating AS EC key from configured private key: " + e.getMessage());
        }
    }

    private ECKey generateEphemeralEcKey() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();

            return buildWithThumbprintKid(
                    (ECPublicKey) kp.getPublic(),
                    (ECPrivateKey) kp.getPrivate()
            );
        } catch (Exception e) {
            throw new ECKeyCreationException("Error generating ephemeral AS EC key: " + e.getMessage());
        }
    }

    private ECKey buildWithThumbprintKid(ECPublicKey publicKey, ECPrivateKey privateKey) throws JOSEException {
        ECKey ecKey = new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .build();
        String thumbprint = ecKey.computeThumbprint().toString();
        log.info("AS key initialized with kid (JWK Thumbprint): {}", thumbprint);
        return new ECKey.Builder(ecKey)
                .keyID(thumbprint)
                .build();
    }
}
