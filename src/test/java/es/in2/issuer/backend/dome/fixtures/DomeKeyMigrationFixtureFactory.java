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

/**
 * Static factory that produces synthetic test fixtures for DOME key-migration
 * integration tests.
 *
 * <p>All key material generated here is ephemeral and used only within the test
 * JVM — no real credentials or secrets are created.
 */
public final class DomeKeyMigrationFixtureFactory {

    private DomeKeyMigrationFixtureFactory() {
        // utility class — no instances
    }

    // ------------------------------------------------------------------
    // Key pair helpers
    // ------------------------------------------------------------------

    /**
     * Generates a synthetic EC P-256 key pair for test use.
     *
     * @return a fresh {@link KeyPair} using the {@code secp256r1} curve
     */
    public static KeyPair generateEcP256KeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("EC P-256 key generation failed in test", e);
        }
    }

    /**
     * Signs {@code data} using ECDSA-SHA-256 (ES256) with the provided EC private key.
     *
     * @param key  the EC private key — must correspond to a P-256 curve
     * @param data the payload bytes to sign
     * @return the compact JWS serialization of the resulting signature
     */
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

    // ------------------------------------------------------------------
    // KmsKeyMigration fixtures
    // ------------------------------------------------------------------

    /**
     * Builds a {@link KmsKeyMigration} entity in {@code PENDING} state
     * suitable for insertion into the test database.
     *
     * @param legacyKeyId the synthetic legacy key identifier
     * @return an unsaved entity with a random ID and timestamps set to now
     */
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

    /**
     * Builds a {@link KmsKeyMigration} entity in {@code PLAN_A_OK} state
     * suitable for rollback (EC-03) tests.
     *
     * @param legacyKeyId the synthetic legacy key identifier
     * @return an unsaved entity with status PLAN_A_OK
     */
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

    // ------------------------------------------------------------------
    // MigrationAuditEntry fixtures
    // ------------------------------------------------------------------

    /**
     * Builds a minimal {@link MigrationAuditEntry} for auditing assertions.
     *
     * @param sourceId the credential or key event identifier
     * @param outcome  the audit outcome string (e.g. "OK", "FAILED")
     * @return an unsaved audit entry
     */
    public static MigrationAuditEntry auditEntry(UUID sourceId, String outcome) {
        return MigrationAuditEntry.builder()
                .id(UUID.randomUUID())
                .sourceRecordId(sourceId)
                .migratedAt(Instant.now())
                .replayAttempt(0)
                .outcome(outcome)
                .build();
    }

    // ------------------------------------------------------------------
    // Issuance credential fixtures
    // ------------------------------------------------------------------

    /**
     * Builds an active (non-expired, non-revoked) {@link Issuance} entity.
     *
     * @return a synthetic credential in VALID status, valid for 365 days
     */
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

    /**
     * Builds an expired {@link Issuance} entity (validUntil in the past).
     *
     * @return a synthetic credential that expired yesterday
     */
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

    /**
     * Builds a revoked {@link Issuance} entity.
     *
     * @return a synthetic credential with REVOKED status
     */
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

