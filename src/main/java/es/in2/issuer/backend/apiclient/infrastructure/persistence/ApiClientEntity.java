package es.in2.issuer.backend.apiclient.infrastructure.persistence;

import es.in2.issuer.backend.apiclient.domain.model.AuthorizationStatus;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("api_client")
public record ApiClientEntity(
        @Id
        UUID id,

        @Column("client_id")
        String clientId,

        @Column("authorization_status")
        AuthorizationStatus authorizationStatus,

        @Column("can_trigger_issuance")
        boolean canTriggerIssuance,

        @Column("secret_hash")
        String secretHash,

        @Column("display_name")
        String displayName,

        @Column("created_at")
        Instant createdAt,

        @Column("updated_at")
        Instant updatedAt
) {
}
