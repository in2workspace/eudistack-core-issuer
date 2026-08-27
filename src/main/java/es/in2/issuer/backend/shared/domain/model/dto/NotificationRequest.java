package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

@Builder
public record NotificationRequest(
        // OID4VCI 1.0 FINAL §11.1 names these fields notification_id/event_description
        // (snake_case) in the request body. Without an explicit mapping here, Jackson only
        // matched the literal Java field name (notificationId), so a spec-conformant request
        // deserialized notificationId as null - passing @NotBlank's presence check trivially
        // false and rejecting every conformant call with 400, even though the payload was
        // valid. Went unnoticed because our own Wallet PWA happened to send the same
        // (non-conformant) camelCase key this record always expected (see the companion fix in
        // eudistack-core-wallet-pwa). @JsonAlias keeps accepting the old camelCase key too,
        // so an un-updated wallet build in the field doesn't suddenly start failing.
        @JsonProperty("notification_id") @JsonAlias("notificationId") @NotBlank String notificationId,
        @NotNull NotificationEvent event,
        @JsonProperty("event_description") @JsonAlias("eventDescription") String eventDescription
) {}