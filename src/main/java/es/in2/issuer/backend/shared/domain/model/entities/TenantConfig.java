package es.in2.issuer.backend.shared.domain.model.entities;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("tenant_config")
public record TenantConfig(
        @Id
        UUID id,

        @Column("config_key")
        String configKey,

        @Column("config_value")
        String configValue,

        @Column("description")
        String description,

        @Column("created_at")
        Instant createdAt,

        @Column("updated_at")
        Instant updatedAt
) {
}
