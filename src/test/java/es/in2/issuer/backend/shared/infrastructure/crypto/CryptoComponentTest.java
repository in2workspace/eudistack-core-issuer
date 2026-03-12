package es.in2.issuer.backend.shared.infrastructure.crypto;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptoComponentTest {

    @Mock
    private CryptoConfig cryptoConfig;

    @InjectMocks
    private CryptoComponent cryptoComponent;

    @Test
    void testGetECKey_withConfiguredKey_usesJwkThumbprintAsKid() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        String privateKeyHex = privateKey.getS().toString(16);
        when(cryptoConfig.getPrivateKey()).thenReturn(privateKeyHex);

        ECKey ecKey = cryptoComponent.getECKey();

        assertNotNull(ecKey);
        assertEquals(Curve.P_256, ecKey.getCurve());
        assertNotNull(ecKey.getKeyID());
        // kid should be a JWK Thumbprint (base64url, ~43 chars), not a did:key
        assertFalse(ecKey.getKeyID().startsWith("did:key:"), "kid should not be a did:key");
        // Verify the thumbprint matches
        assertEquals(ecKey.computeThumbprint().toString(), ecKey.getKeyID());
    }

    @Test
    void testGetECKey_withSameKey_producesSameThumbprint() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        String privateKeyHex = privateKey.getS().toString(16);
        when(cryptoConfig.getPrivateKey()).thenReturn(privateKeyHex);

        ECKey ecKey1 = cryptoComponent.getECKey();

        // Recreate to verify determinism
        CryptoComponent secondComponent = new CryptoComponent(cryptoConfig);
        ECKey ecKey2 = secondComponent.getECKey();

        assertEquals(ecKey1.getKeyID(), ecKey2.getKeyID(), "Same key should produce same thumbprint");
        assertEquals(ecKey1.getX(), ecKey2.getX());
        assertEquals(ecKey1.getY(), ecKey2.getY());
    }

    @Test
    void testGetECKey_withNoKey_generatesEphemeral() throws Exception {
        when(cryptoConfig.getPrivateKey()).thenReturn(null);

        ECKey ecKey = cryptoComponent.getECKey();

        assertNotNull(ecKey);
        assertEquals(Curve.P_256, ecKey.getCurve());
        assertNotNull(ecKey.getKeyID());
        assertFalse(ecKey.getKeyID().startsWith("did:key:"));
        assertEquals(ecKey.computeThumbprint().toString(), ecKey.getKeyID());
    }

    @Test
    void testGetECKey_withBlankKey_generatesEphemeral() {
        when(cryptoConfig.getPrivateKey()).thenReturn("   ");

        ECKey ecKey = cryptoComponent.getECKey();

        assertNotNull(ecKey);
        assertEquals(Curve.P_256, ecKey.getCurve());
    }
}
