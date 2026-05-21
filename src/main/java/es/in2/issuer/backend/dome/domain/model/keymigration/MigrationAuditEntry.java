package es.in2.issuer.backend.dome.domain.model.keymigration;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.annotation.Id;
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
@Table("migration_audit")
public class MigrationAuditEntry {

    @Id
    @Column("id")
    private UUID id;

    @Column("source_record_id")
    private UUID sourceRecordId;

    @Column("target_record_id")
    private UUID targetRecordId;

    @Column("source_hash")
    private String sourceHash;

    @Column("target_hash")
    private String targetHash;

    @Column("migrated_at")
    private Instant migratedAt;

    @Column("replay_attempt")
    private int replayAttempt;

    @Column("outcome")
    private String outcome;

    @Column("error_message")
    private String errorMessage;
}

