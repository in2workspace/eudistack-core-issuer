package es.in2.issuer.backend.dome.domain.model.keymigration;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("dome_key_migration")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DomeKeyMigration {

    @Id
    @Column("id")
    private UUID id;

    @Column("legacy_key_id")
    private String legacyKeyId;

    @Column("migration_status")
    private String migrationStatus;

    @Column("notes")
    private String notes;

    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    @LastModifiedDate
    @Column("updated_at")
    private Instant updatedAt;
}

