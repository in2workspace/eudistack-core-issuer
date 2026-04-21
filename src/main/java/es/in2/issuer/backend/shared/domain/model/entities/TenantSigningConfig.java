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

        @Column("remote_type")
        String remoteType,

        @Column("remote_url")
        String remoteUrl,

        @Column("remote_sign_path")
        String remoteSignPath,

        @Column("remote_client_id")
        String remoteClientId,

        @Column("remote_client_secret")
        String remoteClientSecret,

        @Column("remote_credential_id")
        String remoteCredentialId,

        @Column("remote_credential_pwd")
        String remoteCredentialPwd,

        @Column("remote_cert_cache_ttl")
        String remoteCertCacheTtl,

        @Column("created_at")
        Instant createdAt,

        @Column("updated_at")
        Instant updatedAt
) {
}
