package es.in2.issuer.backend.shared.infrastructure.persistence;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * The own-key block of an {@code own_key} signing configuration, one row per configuration. Signing reads
 * the key reference, the algorithm and the certificate chain; the certificate details are not mapped here:
 * they are read from the chain whenever they are needed.
 */
@Table("tenant_own_key")
public record TenantOwnKeyEntity(
        @Id
        @Column("signing_configuration_id")
        UUID signingConfigurationId,

        @Column("kms_key_ref")
        String kmsKeyRef,

        @Column("algorithm")
        String algorithm,

        @Column("certificate_chain")
        String certificateChain,

        @Column("loaded_at")
        Instant loadedAt,

        @Column("deleted_at")
        Instant deletedAt
) {
}
