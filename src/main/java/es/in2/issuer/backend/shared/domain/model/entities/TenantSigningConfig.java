package es.in2.issuer.backend.shared.domain.model.entities;

import com.fasterxml.jackson.databind.JsonNode;
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

        @Column("provider_specific_config")
        String providerSpecificConfig,

        @Column("created_at")
        Instant createdAt,

        @Column("updated_at")
        Instant updatedAt
) {
}
