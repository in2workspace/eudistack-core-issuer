package es.in2.issuer.backend.dome.fixtures;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.DomeSigningKey;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;

public final class DomeKeyMigrationFixtureFactory {

    private DomeKeyMigrationFixtureFactory() {}

    public static KeyPair generateEcP256KeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate EC P-256 key pair", e);
        }
    }

    public static DomeKeyMigration pendingMigration(String legacyKeyId) {
        return DomeKeyMigration.builder()
                .legacyKeyId(legacyKeyId)
                .migrationStatus(MigrationStatus.PENDING.name())
                .build();
    }

    public static DomeKeyMigration pocOkMigration(String legacyKeyId) {
        return DomeKeyMigration.builder()
                .legacyKeyId(legacyKeyId)
                .migrationStatus(MigrationStatus.POC_OK.name())
                .build();
    }

    public static DomeSigningKey activeDomeSigningKey(String legacyKeyId, byte[] keyMaterial) {
        return DomeSigningKey.builder()
                .keyId(UUID.randomUUID().toString())
                .holderId(legacyKeyId)
                .credentialId(legacyKeyId)
                .tenantId("localhost")
                .privateKey(keyMaterial)
                .publicJwk("{\"kty\":\"EC\",\"crv\":\"P-256\"}")
                .algorithm("ES256")
                .format("dc+sd-jwt")
                .build();
    }
}
