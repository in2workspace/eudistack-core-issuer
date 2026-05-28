package es.in2.issuer.backend.dome.domain.model.keymigration;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("dome_signing_key")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DomeSigningKey {

    @Id
    @Column("id")
    private UUID id;

    @Column("legacy_key_id")
    private String legacyKeyId;

    @Column("key_material")
    private byte[] keyMaterial;

    @Column("key_type")
    private String keyType;

    @Column("active")
    private boolean active;

    @Column("created_at")
    private Instant createdAt;

    @Override
    public String toString() {
        return "DomeSigningKey[id=" + id + ", legacyKeyId=" + legacyKeyId + ", keyMaterial=REDACTED]";
    }
}

