package es.in2.issuer.backend.dome.domain.model.keymigration;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Table("kms_key_migration")
public class KmsKeyMigration {

    @Id
    @Column("id")
    private UUID id;

    @Column("legacy_key_id")
    private String legacyKeyId;

    @Column("kms_alias")
    private String kmsAlias;

    @Column("migration_status")
    private String migrationStatus;

    @Column("migrated_at")
    private Instant migratedAt;

    @Column("audit_evidence_uri")
    private String auditEvidenceUri;

    @Column("replay_attempt")
    private int replayAttempt;

    @Column("notes")
    private String notes;

    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    @LastModifiedDate
    @Column("updated_at")
    private Instant updatedAt;
}

