package es.in2.issuer.backend.shared.domain.model.audit;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds the audit entries of an issuance process (EUD-4, EUD-167). The process is the {@code resource}
 * ({@code issuance:{id}}) and its id the correlation id of every event of the operation, so the entries
 * only carry what the step itself knows. A field the step did not get to know is left {@code null} and
 * omitted, never invented.
 */
public final class IssuanceAuditEvents {

    private static final String ATTESTATION_TYPE = "attestation_type";
    private static final String DELIVERY_METHOD = "delivery_method";
    private static final String HOLDER = "holder";
    private static final String ISSUANCE_MODE_THIRD_PARTY = "ThirdParty";
    /** Scope of a listing made for no particular organization, such as an administrator's view of the whole tenant. */
    private static final String SCOPE_TENANT = "tenant";

    /** Whether an offer is the first one of the process or a new one asked for while it is still a draft. */
    public enum OfferKind {
        INITIAL("Initial"),
        REISSUED("Reissued");

        private final String catalogValue;

        OfferKind(String catalogValue) {
            this.catalogValue = catalogValue;
        }
    }

    /** The person an attestation is for, in clear, as the catalogue's {@code person} type. */
    public record Holder(String identifier, String name, String email) {

        public Map<String, Object> toDetails() {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("identifier", identifier);
            details.put("name", name);
            details.put("email", email);
            return details;
        }
    }

    /** The wallet exchange that delivered an attestation. */
    public record WalletInteraction(String protocol, String grantType, String format) {

        Map<String, Object> toDetails() {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("protocol", protocol);
            details.put("grant_type", grantType);
            details.put("format", format);
            return details;
        }
    }

    /** The organization that issues: the holder of the certificate the attestation is signed with. */
    public record Provider(String legalName, String registrationId) {

        public boolean isComplete() {
            return legalName != null && !legalName.isBlank() && registrationId != null && !registrationId.isBlank();
        }
    }

    /** What the flow knows of an attestation it has just delivered; {@code walletInteraction} is null when it was not delivered through a wallet. */
    public record Completion(String attestationType, String deliveryMethod, Holder holder, List<String> issuedAttributes,
                             Instant validFrom, Instant validUntil, WalletInteraction walletInteraction) {
    }

    private IssuanceAuditEvents() {
    }

    /** A validity bound stored with the process, which may not be set. */
    public static Instant instantOf(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    public static String resourceOf(String issuanceId) {
        return "issuance:" + issuanceId;
    }

    /**
     * The catalogue's {@code delivery_method} is a single value while the Issuer accepts several modes at
     * once. A wallet delivery by email is reported as {@code email}, otherwise a wallet delivery by link
     * as {@code ui}, and only a direct one as {@code direct}.
     */
    public static String deliveryMethodOf(String delivery) {
        Set<DeliveryMode> modes = DeliveryMode.parse(delivery);
        if (modes.contains(DeliveryMode.EMAIL)) {
            return DeliveryMode.EMAIL.value;
        }
        if (modes.contains(DeliveryMode.UI)) {
            return DeliveryMode.UI.value;
        }
        return DeliveryMode.DIRECT.value;
    }

    /** True when the delivery goes through the wallet, which is when the offer has an expiry. */
    public static boolean hasOffer(String deliveryMethod) {
        return !DeliveryMode.DIRECT.value.equals(deliveryMethod);
    }

    public static AuditEntry requested(String issuanceId, String attestationType, String deliveryMethod,
                                       Holder holder, Instant offerExpiresAt) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put(ATTESTATION_TYPE, attestationType);
        details.put("issuance_mode", ISSUANCE_MODE_THIRD_PARTY);
        details.put(DELIVERY_METHOD, deliveryMethod);
        details.put(HOLDER, holder.toDetails());
        details.put("offer_expires_at", hasOffer(deliveryMethod) ? offerExpiresAt : null);
        return AuditEntry.success(AuditEventType.ISSUANCE_REQUESTED, resourceOf(issuanceId), details);
    }

    /**
     * An attestation that was signed and delivered. The certificate and the attestation itself travel only
     * as fingerprints.
     */
    public static AuditEntry completed(String issuanceId, Provider provider, Completion completion,
                                       String signatureAlgorithm, String signingCertificate, String attestationHash) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("provider_legal_name", provider.legalName());
        details.put("provider_registration_id", provider.registrationId());
        details.put(ATTESTATION_TYPE, completion.attestationType());
        details.put(DELIVERY_METHOD, completion.deliveryMethod());
        details.put(HOLDER, completion.holder().toDetails());
        details.put("issued_attributes", completion.issuedAttributes());
        details.put("valid_from", completion.validFrom());
        details.put("valid_until", completion.validUntil());
        details.put("signing_certificate", signingCertificate);
        details.put("signature_algorithm", signatureAlgorithm);
        details.put("attestation_hash", attestationHash);
        if (completion.walletInteraction() != null) {
            details.put("wallet_interaction", completion.walletInteraction().toDetails());
            details.put("accepted_by_holder", true);
        }
        return AuditEntry.success(AuditEventType.ISSUANCE_COMPLETED, resourceOf(issuanceId), details);
    }

    /**
     * An issuance that did not complete. It carries what was known when it failed: the attestation type, the
     * delivery method and the holder, each only if the step got to know it.
     */
    public static AuditEntry attemptFailed(String issuanceId, String reason, String attestationType,
                                           String deliveryMethod, Holder holder) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put(ATTESTATION_TYPE, attestationType);
        details.put(DELIVERY_METHOD, deliveryMethod);
        details.put(HOLDER, holder == null ? null : holder.toDetails());
        return AuditEntry.forReason(AuditEventType.ISSUANCE_ATTEMPT_FAILED, resourceOf(issuanceId), reason, details);
    }

    /**
     * A list of issuance processes. The list endpoint takes no filters, so {@code filters} is empty;
     * {@code scope} identifies who was listed for, {@code <kind>:<id>} being the catalogue's resource form.
     */
    public static AuditEntry queried(String scope, int returnedCount) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("filters", Map.of());
        details.put("returned_count", returnedCount);
        String listedFor = scope == null || scope.isBlank() ? SCOPE_TENANT : scope;
        return AuditEntry.success(AuditEventType.ISSUANCE_QUERIED, "issuance-list:" + listedFor, details);
    }

    /** The detail of one process, with the holder it is for. */
    public static AuditEntry detailAccessed(String issuanceId, Holder holder) {
        return AuditEntry.success(AuditEventType.ISSUANCE_DETAIL_ACCESSED, resourceOf(issuanceId),
                Map.of(HOLDER, holder.toDetails()));
    }

    public static AuditEntry detailRefused(String issuanceId, String reason) {
        return AuditEntry.forReason(AuditEventType.ISSUANCE_DETAIL_ACCESSED, resourceOf(issuanceId), reason, Map.of());
    }

    /** A draft that is withdrawn. The type declares no details. */
    public static AuditEntry withdrawn(String issuanceId) {
        return AuditEntry.success(AuditEventType.ISSUANCE_WITHDRAWN, resourceOf(issuanceId), Map.of());
    }

    public static AuditEntry withdrawalRefused(String issuanceId, String reason) {
        return AuditEntry.forReason(AuditEventType.ISSUANCE_WITHDRAWN, resourceOf(issuanceId), reason, Map.of());
    }

    /** A finished process that is archived. The type declares no details. */
    public static AuditEntry archived(String issuanceId) {
        return AuditEntry.success(AuditEventType.ISSUANCE_ARCHIVED, resourceOf(issuanceId), Map.of());
    }

    public static AuditEntry archiveRefused(String issuanceId, String reason) {
        return AuditEntry.forReason(AuditEventType.ISSUANCE_ARCHIVED, resourceOf(issuanceId), reason, Map.of());
    }

    /**
     * An accepted notification of the wallet. {@code revoked} is whether it ended up revoking the
     * attestation, so a revocation that could not be applied is not reported as one that happened.
     */
    public static AuditEntry notificationReceived(String issuanceId, String notificationEvent, boolean revoked) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("notification_event", notificationEvent);
        details.put("resulting_action", revoked ? "Revoked" : "None");
        return AuditEntry.success(AuditEventType.WALLET_NOTIFICATION_RECEIVED, resourceOf(issuanceId), details);
    }

    public static AuditEntry offerSent(String issuanceId, OfferKind kind, String recipientEmail,
                                       Instant offerExpiresAt, boolean mailDelivered) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("offer_kind", kind.catalogValue);
        details.put("recipient_email", recipientEmail);
        details.put("offer_expires_at", offerExpiresAt);
        String resource = resourceOf(issuanceId);
        return mailDelivered
                ? AuditEntry.success(AuditEventType.CREDENTIAL_OFFER_SENT, resource, details)
                : AuditEntry.failure(AuditEventType.CREDENTIAL_OFFER_SENT, resource, "MailDeliveryFailed", details);
    }
}
