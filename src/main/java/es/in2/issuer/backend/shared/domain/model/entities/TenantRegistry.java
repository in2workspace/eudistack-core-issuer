package es.in2.issuer.backend.shared.domain.model.entities;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table("tenant_registry")
public record TenantRegistry(
        @Id
        @Column("schema_name")
        String schemaName,

        @Column("display_name")
        String displayName,

        @Column("tenant_type")
        String tenantType,

        @Column("status")
        String status,

        @Column("created_at")
        Instant createdAt,

        @Column("updated_at")
        Instant updatedAt
) {
}
