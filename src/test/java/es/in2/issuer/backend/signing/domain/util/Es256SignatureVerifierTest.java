package es.in2.issuer.backend.signing.domain.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Es256SignatureVerifierTest {

    private static final String SIGNING_INPUT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0";

    private final OwnKeyTestPki pki = new OwnKeyTestPki();

    @Test
    void verify_validSignature_returnsTrue() throws Exception {
        var leaf = pki.validP256Leaf();

        assertThat(Es256SignatureVerifier.verify(SIGNING_INPUT, sign(leaf.keyPair()), leaf.certificate())).isTrue();
    }

    @Test
    void verify_signatureOfAnotherKey_returnsFalse() throws Exception {
        var signer = pki.validP256Leaf();
        var other = pki.expiredLeaf();

        assertThat(Es256SignatureVerifier.verify(SIGNING_INPUT, sign(signer.keyPair()), other.certificate()))
                .isFalse();
    }

    @Test
    void verify_alteredSigningInput_returnsFalse() throws Exception {
        var leaf = pki.validP256Leaf();

        assertThat(Es256SignatureVerifier.verify(SIGNING_INPUT + "x", sign(leaf.keyPair()), leaf.certificate()))
                .isFalse();
    }

    @Test
    void verify_wrongSignatureLength_returnsFalse() throws Exception {
        var leaf = pki.validP256Leaf();
        byte[] signature = sign(leaf.keyPair());

        assertThat(Es256SignatureVerifier.verify(SIGNING_INPUT, java.util.Arrays.copyOf(signature, 63),
                leaf.certificate())).isFalse();
        assertThat(Es256SignatureVerifier.verify(SIGNING_INPUT, java.util.Arrays.copyOf(signature, 65),
                leaf.certificate())).isFalse();
    }

    @Test
    void verify_derEncodedSignature_returnsFalse() throws Exception {
        var leaf = pki.validP256Leaf();
        java.security.Signature ecdsa = java.security.Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(leaf.keyPair().getPrivate());
        ecdsa.update(SIGNING_INPUT.getBytes(StandardCharsets.US_ASCII));

        assertThat(Es256SignatureVerifier.verify(SIGNING_INPUT, ecdsa.sign(), leaf.certificate())).isFalse();
    }

    @Test
    void verify_rsaCertificate_returnsFalse() {
        assertThat(Es256SignatureVerifier.verify(SIGNING_INPUT, new byte[64], pki.rsaLeaf().certificate()))
                .isFalse();
    }

    @Test
    void verify_p384Certificate_returnsFalse() {
        assertThat(Es256SignatureVerifier.verify(SIGNING_INPUT, new byte[64], pki.p384Leaf().certificate()))
                .isFalse();
    }

    @Test
    void verify_signaturesWithHighBitAndLeadingZeroComponents_areAllAccepted() throws Exception {
        // R and S are fixed 32-byte fields: about half have the high bit set (DER needs a 0x00 sign
        // byte) and 1 in 256 start with a zero octet (DER INTEGER is shorter than 32 bytes).
        var leaf = pki.validP256Leaf();
        boolean sawHighBit = false;
        boolean sawLeadingZero = false;
        for (int i = 0; i < 3_000; i++) {
            String input = SIGNING_INPUT + i;
            byte[] signature = new ECDSASigner((ECPrivateKey) leaf.keyPair().getPrivate())
                    .sign(new JWSHeader(JWSAlgorithm.ES256), input.getBytes(StandardCharsets.US_ASCII)).decode();
            sawHighBit |= (signature[0] & 0x80) != 0 || (signature[32] & 0x80) != 0;
            sawLeadingZero |= signature[0] == 0 || signature[32] == 0;

            assertThat(Es256SignatureVerifier.verify(input, signature, leaf.certificate())).isTrue();
        }
        assertThat(sawHighBit).isTrue();
        assertThat(sawLeadingZero).isTrue();
    }

    @Test
    void verify_allZeroSignature_returnsFalse() {
        assertThat(Es256SignatureVerifier.verify(SIGNING_INPUT, new byte[64], pki.validP256Leaf().certificate()))
                .isFalse();
    }

    @Test
    void verify_nullArguments_throw() {
        var certificate = pki.validP256Leaf().certificate();

        assertThatThrownBy(() -> Es256SignatureVerifier.verify(null, new byte[64], certificate))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Es256SignatureVerifier.verify(SIGNING_INPUT, null, certificate))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Es256SignatureVerifier.verify(SIGNING_INPUT, new byte[64], null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** Produces the R||S signature Nimbus would put in the third JWS segment. */
    private static byte[] sign(KeyPair keyPair) throws Exception {
        Base64URL signature = new ECDSASigner((ECPrivateKey) keyPair.getPrivate())
                .sign(new JWSHeader(JWSAlgorithm.ES256), SIGNING_INPUT.getBytes(StandardCharsets.US_ASCII));
        return signature.decode();
    }
}
