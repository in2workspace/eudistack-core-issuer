package es.in2.issuer.backend.shared.domain.model.entities;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("tenant_signing_config")
public record TenantSigningConfig(
        @Id
        UUID id,

        @Column("provider")
        String provider,

        @Column("csc_api_version")
        String cscApiVersion,

        @Column("provider_specific_config")
        String providerSpecificConfig,

        @Column("created_at")
        Instant createdAt,

        @Column("updated_at")
        Instant updatedAt,

        @Column("modality")
        String modality,

        @Column("status")
        String status,

        @Column("activated_at")
        Instant activatedAt,

        @Column("withdrawn_at")
        Instant withdrawnAt,

        @Column("own_key_kms_key_ref")
        String ownKeyKmsKeyRef,

        @Column("own_key_algorithm")
        String ownKeyAlgorithm,

        @Column("own_key_certificate_chain")
        String ownKeyCertificateChain,

        @Column("own_key_spki_sha256")
        String ownKeySpkiSha256,

        @Column("own_key_loaded_at")
        Instant ownKeyLoadedAt,

        @Column("own_key_deleted_at")
        Instant ownKeyDeletedAt
) {
}
