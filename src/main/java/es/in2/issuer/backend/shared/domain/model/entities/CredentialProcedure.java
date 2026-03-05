package es.in2.issuer.backend.shared.domain.model.entities;

import jakarta.annotation.Nullable;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import lombok.*;
import org.springframework.data.annotation.*;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Table("issuer.credential_procedure")
public class CredentialProcedure {
    @Id
    @Column("procedure_id")
    private UUID procedureId;

    @Column("credential_format")
    private String credentialFormat;

    @Column("credential_data_set")
    private String credentialDataSet;

    @Column("credential_status")
    private CredentialStatusEnum credentialStatus;

    @Column("organization_identifier")
    private String organizationIdentifier;

    @Column("subject")
    @Nullable
    private String subject;

    @Column("credential_type")
    private String credentialType;

    @Column("valid_until")
    private Timestamp validUntil;

    @Column("email")
    private String email;

    @Column("delivery")
    private String delivery;

    @Column("refresh_token")
    private String refreshToken;

    @Column("notification_id")
    private UUID notificationId;

    // --- Auditing fields (R2DBC auditing will fill these) ---
    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    @LastModifiedDate
    @Column("updated_at")
    private Instant updatedAt;

    @CreatedBy
    @Column("created_by")
    private String createdBy;

    @LastModifiedBy
    @Column("updated_by")
    private String updatedBy;
    // --------------------------------------------------------
}
