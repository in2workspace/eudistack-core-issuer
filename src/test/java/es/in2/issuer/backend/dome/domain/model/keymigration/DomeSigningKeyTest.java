package es.in2.issuer.backend.dome.domain.model.keymigration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("DomeSigningKey — domain entity")
class DomeSigningKeyTest {

    @Test
    @DisplayName("isActive — when revokedAt is null — returns true")
    void isActive_whenRevokedAtIsNull_returnsTrue() {
        DomeSigningKey key = DomeSigningKey.builder()
                .keyId("key-1")
                .holderId("holder-1")
                .revokedAt(null)
                .build();

        assertThat(key.isActive()).isTrue();
    }

    @Test
    @DisplayName("isActive — when revokedAt is set — returns false")
    void isActive_whenRevokedAtIsSet_returnsFalse() {
        DomeSigningKey key = DomeSigningKey.builder()
                .keyId("key-1")
                .holderId("holder-1")
                .revokedAt(Instant.now())
                .build();

        assertThat(key.isActive()).isFalse();
    }

    @Test
    @DisplayName("toString — does not expose privateKey bytes")
    void toString_doesNotExposePrivateKey() {
        DomeSigningKey key = DomeSigningKey.builder()
                .keyId("key-abc")
                .holderId("holder-xyz")
                .privateKey(new byte[]{1, 2, 3, 4})
                .build();

        String str = key.toString();

        assertThat(str).contains("key-abc");
        assertThat(str).contains("holder-xyz");
        assertThat(str).contains("REDACTED");
        assertThat(str).doesNotContain("1, 2, 3, 4");
    }

    @Test
    @DisplayName("builder — all fields set — getters return correct values")
    void builder_allFieldsSet_gettersReturnCorrectValues() {
        Instant now = Instant.now();
        DomeSigningKey key = DomeSigningKey.builder()
                .keyId("k1")
                .holderId("h1")
                .credentialId("c1")
                .tenantId("t1")
                .privateKey(new byte[]{9})
                .publicJwk("{\"kty\":\"EC\"}")
                .algorithm("ES256")
                .format("dc+sd-jwt")
                .createdAt(now)
                .build();

        assertThat(key.getKeyId()).isEqualTo("k1");
        assertThat(key.getHolderId()).isEqualTo("h1");
        assertThat(key.getCredentialId()).isEqualTo("c1");
        assertThat(key.getTenantId()).isEqualTo("t1");
        assertThat(key.getPublicJwk()).isEqualTo("{\"kty\":\"EC\"}");
        assertThat(key.getAlgorithm()).isEqualTo("ES256");
        assertThat(key.getFormat()).isEqualTo("dc+sd-jwt");
        assertThat(key.getCreatedAt()).isEqualTo(now);
    }
}

