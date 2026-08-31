package es.in2.issuer.backend.signing.domain.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.Signature;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwsSignatureEncoderTest {

    @Test
    void toJoseSignature_derEcdsaSignature_isTranscodedAndVerifies() throws Exception {
        // Arrange — sign like a CSC QTSP does: raw ECDSA primitive, ASN.1 DER output
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        String signingInput = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzdGF0dXMtbGlzdCJ9";

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(key.toECPrivateKey());
        ecdsa.update(signingInput.getBytes());
        byte[] derSignature = ecdsa.sign();
        String qtspSignature = Base64.getEncoder().encodeToString(derSignature);

        // Act
        String joseSignature = JwsSignatureEncoder.toJoseSignature(qtspSignature, JWSAlgorithm.ES256);

        // Assert — R || S, 64 bytes, and accepted by a conformant JOSE verifier
        assertThat(derSignature[0]).isEqualTo((byte) 0x30);
        assertThat(new Base64URL(joseSignature).decode()).hasSize(64);
        assertThat(joseSignature).doesNotContain("+").doesNotContain("/").doesNotContain("=");

        SignedJWT jwt = SignedJWT.parse(signingInput + "." + joseSignature);
        assertThat(jwt.verify(new ECDSAVerifier(key.toECPublicKey()))).isTrue();
    }

    @Test
    void toJoseSignature_alreadyConcatEcdsaSignature_isLeftUnchanged() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader(JWSAlgorithm.ES256),
                new JWTClaimsSet.Builder().subject("status-list").build());
        jwt.sign(new ECDSASigner(key));
        String concatSignature = jwt.getSignature().toString();

        String joseSignature = JwsSignatureEncoder.toJoseSignature(concatSignature, JWSAlgorithm.ES256);

        assertThat(joseSignature).isEqualTo(concatSignature);
    }

    @Test
    void toJoseSignature_rsaSignature_isOnlyRebasedToBase64Url() {
        // A byte sequence whose standard Base64 contains both + and /
        byte[] rsaSignature = BigInteger.valueOf(0xFBFF).toByteArray();
        String standardBase64 = Base64.getEncoder().encodeToString(rsaSignature);

        String joseSignature = JwsSignatureEncoder.toJoseSignature(standardBase64, JWSAlgorithm.RS256);

        assertThat(new Base64URL(joseSignature).decode()).isEqualTo(rsaSignature);
    }

    @Test
    void toJoseSignature_derSignatureAsLongAsTheConcatForm_isStillTranscoded() {
        // A DER SEQUENCE measures 6 + len(R) + len(S) for ES256. With a 32-byte R and a
        // 26-byte S that is exactly 64 bytes — the same length as the JOSE concat form — so
        // a length-based "already concat" test would pass the DER blob through untouched.
        byte[] r = filled(32, (byte) 0x7A);
        byte[] s = filled(26, (byte) 0x5B);
        byte[] der = der(r, s);
        assertThat(der).hasSize(64);

        String joseSignature = JwsSignatureEncoder.toJoseSignature(
                Base64.getUrlEncoder().withoutPadding().encodeToString(der), JWSAlgorithm.ES256);

        // R || S with S left-padded to the fixed 32-byte field
        byte[] expected = new byte[64];
        System.arraycopy(r, 0, expected, 0, 32);
        System.arraycopy(s, 0, expected, 64 - s.length, s.length);
        assertThat(new Base64URL(joseSignature).decode()).isEqualTo(expected);
    }

    @Test
    void toJoseSignature_concatSignatureStartingWithDerSequenceTag_isLeftUnchanged() {
        // R starts with 0x30, the DER SEQUENCE tag, but the following octet does not declare a
        // length spanning the buffer, so the structural check must not treat this as DER.
        byte[] concat = filled(64, (byte) 0x11);
        concat[0] = 0x30;
        concat[1] = 0x00;
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(concat);

        String joseSignature = JwsSignatureEncoder.toJoseSignature(encoded, JWSAlgorithm.ES256);

        assertThat(new Base64URL(joseSignature).decode()).isEqualTo(concat);
    }

    private static byte[] filled(int length, byte value) {
        byte[] bytes = new byte[length];
        java.util.Arrays.fill(bytes, value);
        return bytes;
    }

    /** Assembles {@code SEQUENCE { INTEGER r, INTEGER s }} in the DER short length form. */
    private static byte[] der(byte[] r, byte[] s) {
        int content = 2 + r.length + 2 + s.length;
        byte[] out = new byte[2 + content];
        out[0] = 0x30;
        out[1] = (byte) content;
        out[2] = 0x02;
        out[3] = (byte) r.length;
        System.arraycopy(r, 0, out, 4, r.length);
        out[4 + r.length] = 0x02;
        out[5 + r.length] = (byte) s.length;
        System.arraycopy(s, 0, out, 6 + r.length, s.length);
        return out;
    }

    @Test
    void toJoseSignature_ecdsaSignatureNeitherDerNorConcat_throws() {
        String malformed = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{0x01, 0x02, 0x03});

        assertThatThrownBy(() -> JwsSignatureEncoder.toJoseSignature(malformed, JWSAlgorithm.ES256))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("neither DER nor ES256");
    }

    @Test
    void toJoseSignature_blankSignature_throws() {
        assertThatThrownBy(() -> JwsSignatureEncoder.toJoseSignature("  ", JWSAlgorithm.ES256))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toJoseSignature_nullAlgorithm_throws() {
        assertThatThrownBy(() -> JwsSignatureEncoder.toJoseSignature("AAAA", null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
