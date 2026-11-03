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
        String status
) {
}
