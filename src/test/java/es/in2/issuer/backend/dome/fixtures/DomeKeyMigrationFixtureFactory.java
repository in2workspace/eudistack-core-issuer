package es.in2.issuer.backend.dome.fixtures;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationAuditEntry;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

public final class DomeKeyMigrationFixtureFactory {

    private DomeKeyMigrationFixtureFactory() {
        // utility class — no instances
    }

    public static KeyPair generateEcP256KeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("EC P-256 key generation failed in test", e);
        }
    }

    public static String signWithEcKey(PrivateKey key, byte[] data) {
        try {
            ECDSASigner signer = new ECDSASigner((ECPrivateKey) key);
            JWSObject jws = new JWSObject(
                    new JWSHeader(JWSAlgorithm.ES256),
                    new Payload(data));
            jws.sign(signer);
            return jws.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("ES256 signing failed in test fixture", e);
        }
    }

    public static KmsKeyMigration pendingMigration(String legacyKeyId) {
        return KmsKeyMigration.builder()
                .id(UUID.randomUUID())
                .legacyKeyId(legacyKeyId)
                .kmsAlias("alias/dome/signing")
                .migrationStatus(MigrationStatus.PENDING.name())
                .replayAttempt(0)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
    }

    public static KmsKeyMigration pocOkMigration(String legacyKeyId) {
        return KmsKeyMigration.builder()
                .id(UUID.randomUUID())
                .legacyKeyId(legacyKeyId)
                .kmsAlias("alias/dome/signing")
                .migrationStatus(MigrationStatus.POC_OK.name())
                .replayAttempt(0)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
    }

    public static KmsKeyMigration planAOkMigration(String legacyKeyId) {
        return KmsKeyMigration.builder()
                .id(UUID.randomUUID())
                .legacyKeyId(legacyKeyId)
                .kmsAlias("alias/dome/signing")
                .migrationStatus(MigrationStatus.PLAN_A_OK.name())
                .replayAttempt(0)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
    }

    public static MigrationAuditEntry auditEntry(UUID sourceId, String outcome) {
        return MigrationAuditEntry.builder()
                .id(UUID.randomUUID())
                .sourceRecordId(sourceId)
                .migratedAt(Instant.now())
                .replayAttempt(0)
                .outcome(outcome)
                .build();
    }

    public static Issuance activeIssuance() {
        Instant now = Instant.now();
        return Issuance.builder()
                .issuanceId(UUID.randomUUID())
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{\"type\":\"SyntheticCredential\"}")
                .credentialStatus(CredentialStatusEnum.VALID)
                .organizationIdentifier("test-org")
                .credentialType("SyntheticCredential")
                .validFrom(Timestamp.from(now.minus(1, ChronoUnit.DAYS)))
                .validUntil(Timestamp.from(now.plus(365, ChronoUnit.DAYS)))
                .subject("{}")
                .build();
    }

    public static Issuance expiredIssuance() {
        Instant now = Instant.now();
        return Issuance.builder()
                .issuanceId(UUID.randomUUID())
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{\"type\":\"SyntheticCredential\"}")
                .credentialStatus(CredentialStatusEnum.VALID)
                .organizationIdentifier("test-org")
                .credentialType("SyntheticCredential")
                .validFrom(Timestamp.from(now.minus(10, ChronoUnit.DAYS)))
                .validUntil(Timestamp.from(now.minus(1, ChronoUnit.DAYS)))
                .subject("{}")
                .build();
    }

    public static Issuance revokedIssuance() {
        Instant now = Instant.now();
        return Issuance.builder()
                .issuanceId(UUID.randomUUID())
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{\"type\":\"SyntheticCredential\"}")
                .credentialStatus(CredentialStatusEnum.REVOKED)
                .organizationIdentifier("test-org")
                .credentialType("SyntheticCredential")
                .validFrom(Timestamp.from(now.minus(10, ChronoUnit.DAYS)))
                .validUntil(Timestamp.from(now.plus(365, ChronoUnit.DAYS)))
                .subject("{}")
                .build();
    }
}
