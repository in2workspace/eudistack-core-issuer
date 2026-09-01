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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.Signature;
import java.util.Base64;
import java.util.stream.Stream;

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

    /** Assembles {@code SEQUENCE { INTEGER r, INTEGER s }}, switching to the long length form above 127 octets. */
    private static byte[] der(byte[] r, byte[] s) {
        int content = 2 + r.length + 2 + s.length;
        int header = content > 0x7F ? 3 : 2;
        byte[] out = new byte[header + content];
        out[0] = 0x30;
        if (header == 3) {
            out[1] = (byte) 0x81;
            out[2] = (byte) content;
        } else {
            out[1] = (byte) content;
        }
        out[header] = 0x02;
        out[header + 1] = (byte) r.length;
        System.arraycopy(r, 0, out, header + 2, r.length);
        out[header + 2 + r.length] = 0x02;
        out[header + 3 + r.length] = (byte) s.length;
        System.arraycopy(s, 0, out, header + 4 + r.length, s.length);
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
    void toJoseSignature_es512DerSignatureInLongFormLength_isTranscoded() {
        // P-521: the SEQUENCE content exceeds 127 octets, so DER switches to the single-octet
        // long length form (0x81) that isDerSequence must also recognize.
        byte[] r = filled(66, (byte) 0x7C);
        byte[] s = filled(66, (byte) 0x6D);
        byte[] der = der(r, s);
        assertThat(der[1] & 0xFF).isEqualTo(0x81);

        String joseSignature = JwsSignatureEncoder.toJoseSignature(
                Base64.getUrlEncoder().withoutPadding().encodeToString(der), JWSAlgorithm.ES512);

        byte[] expected = new byte[132];
        System.arraycopy(r, 0, expected, 0, 66);
        System.arraycopy(s, 0, expected, 66, 66);
        assertThat(new Base64URL(joseSignature).decode()).isEqualTo(expected);
    }

    /**
     * Every buffer here is 64 octets — the ES256 concat length — and starts with the DER
     * SEQUENCE tag, but none is a well-formed {@code SEQUENCE { INTEGER r, INTEGER s }}. All
     * must be recognized as R||S instead of being handed to Nimbus, which reads the inner
     * lengths without bounds-checking them.
     */
    static Stream<Arguments> malformedDerAtConcatLength() {
        return Stream.of(
                Arguments.of("no INTEGER headers in the content", sequence(0x3E, 0x11, 0x11)),
                Arguments.of("R length overruns the buffer", sequence(0x3E, 0x02, 0x7F)),
                Arguments.of("R length is zero", sequence(0x3E, 0x02, 0x00)),
                Arguments.of("R length uses a reserved octet", sequence(0x3E, 0x02, 0x80)),
                Arguments.of("multi-octet SEQUENCE length prefix", sequence(0x82, 0x02, 0x20)),
                Arguments.of("R is not followed by an INTEGER header", sequence(0x3E, 0x02, 0x10)),
                Arguments.of("S has no INTEGER header", withoutSHeader()),
                Arguments.of("both INTEGERs are valid but shorter than the declared SEQUENCE", shortIntegers())
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("malformedDerAtConcatLength")
    void toJoseSignature_malformedDerAtConcatLength_isTreatedAsConcat(String description, byte[] signature) {
        String joseSignature = JwsSignatureEncoder.toJoseSignature(
                Base64.getUrlEncoder().withoutPadding().encodeToString(signature), JWSAlgorithm.ES256);

        assertThat(new Base64URL(joseSignature).decode()).isEqualTo(signature);
    }

    static Stream<Arguments> malformedDerBelowConcatLength() {
        return Stream.of(
                Arguments.of("SEQUENCE tag alone", new byte[]{0x30}),
                Arguments.of("long form without its length octet", new byte[]{0x30, (byte) 0x81}),
                Arguments.of("empty SEQUENCE", new byte[]{0x30, 0x00})
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("malformedDerBelowConcatLength")
    void toJoseSignature_malformedDerBelowConcatLength_throws(String description, byte[] signature) {
        assertThatThrownBy(() -> JwsSignatureEncoder.toJoseSignature(
                Base64.getUrlEncoder().withoutPadding().encodeToString(signature), JWSAlgorithm.ES256))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("neither DER nor ES256");
    }

    /** 64 octets starting with the SEQUENCE tag, the given length octet and R header bytes. */
    private static byte[] sequence(int lengthOctet, int rTag, int rLength) {
        byte[] bytes = filled(64, (byte) 0x11);
        bytes[0] = 0x30;
        bytes[1] = (byte) lengthOctet;
        bytes[2] = (byte) rTag;
        bytes[3] = (byte) rLength;
        return bytes;
    }

    /** Well-formed 16-octet R and S inside a SEQUENCE that declares 62 octets of content. */
    private static byte[] shortIntegers() {
        byte[] bytes = sequence(0x3E, 0x02, 0x10);
        bytes[20] = 0x02;
        bytes[21] = 0x10;
        return bytes;
    }

    /** Well-formed 32-octet R, then content where the S INTEGER header should be. */
    private static byte[] withoutSHeader() {
        byte[] bytes = sequence(0x3E, 0x02, 0x20);
        bytes[36] = 0x11;
        return bytes;
    }

    @Test
    void toJoseSignature_derIntegersTooWideForTheCurve_throws() {
        // Structurally valid DER, but R and S do not fit the ES256 fixed-width fields, so
        // Nimbus refuses to transcode and no length identifies the value either.
        byte[] der = der(filled(40, (byte) 0x2A), filled(40, (byte) 0x3B));

        assertThatThrownBy(() -> JwsSignatureEncoder.toJoseSignature(
                Base64.getUrlEncoder().withoutPadding().encodeToString(der), JWSAlgorithm.ES256))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("neither DER nor ES256");
    }

    @Test
    void toJoseSignature_notBase64_throws() {
        assertThatThrownBy(() -> JwsSignatureEncoder.toJoseSignature("!!not base64!!", JWSAlgorithm.ES256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not valid Base64");
    }

    @Test
    void toJoseSignature_nullSignature_throws() {
        assertThatThrownBy(() -> JwsSignatureEncoder.toJoseSignature(null, JWSAlgorithm.ES256))
                .isInstanceOf(IllegalArgumentException.class);
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
