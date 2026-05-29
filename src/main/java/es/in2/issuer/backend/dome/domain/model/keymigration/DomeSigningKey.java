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

@Table("holder_key")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DomeSigningKey {

    @Id
    @Column("key_id")
    private String keyId;

    @Column("holder_id")
    private String holderId;

    @Column("credential_id")
    private String credentialId;

    @Column("tenant_id")
    private String tenantId;

    @Column("private_key")
    private byte[] privateKey;

    @Column("public_jwk")
    private String publicJwk;

    @Column("algorithm")
    private String algorithm;

    @Column("format")
    private String format;

    @Column("created_at")
    private Instant createdAt;

    @Column("revoked_at")
    private Instant revokedAt;

    /**
     * Convenience helper: a key is active when it has not been revoked.
     */
    public boolean isActive() {
        return revokedAt == null;
    }

    @Override
    public String toString() {
        return "DomeSigningKey[keyId=" + keyId + ", holderId=" + holderId + ", privateKey=REDACTED]";
    }
}
