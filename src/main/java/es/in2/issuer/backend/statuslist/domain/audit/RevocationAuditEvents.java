package es.in2.issuer.backend.statuslist.domain.audit;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Holder;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the {@code Revocation} entry of a revocation. There is one per request, with its final result:
 * the revocation is applied, or it is refused with a reason of the catalogue. A reason is only sent when
 * the revocation was asked for (origin {@code Request}); a revocation caused by a wallet notification has
 * none, and the holder is left out when the process could not be resolved.
 */
public final class RevocationAuditEvents {

    /** What triggered the revocation, as the catalogue's {@code revocation_origin}. */
    public enum Origin {
        REQUEST("Request"),
        WALLET_NOTIFICATION("WalletNotification");

        private final String catalogValue;

        Origin(String catalogValue) {
            this.catalogValue = catalogValue;
        }
    }

    /** Longest {@code revocation_reason} the catalogue accepts. */
    public static final int MAX_REASON_LENGTH = 280;

    private RevocationAuditEvents() {
    }

    public static AuditEntry applied(String issuanceId, Origin origin, String reason, Holder holder) {
        return AuditEntry.success(AuditEventType.REVOCATION, IssuanceAuditEvents.resourceOf(issuanceId),
                details(origin, reason, holder));
    }

    public static AuditEntry refused(String issuanceId, Origin origin, String catalogReason, String reason,
                                     Holder holder) {
        return AuditEntry.forReason(AuditEventType.REVOCATION, IssuanceAuditEvents.resourceOf(issuanceId),
                catalogReason, details(origin, reason, holder));
    }

    private static Map<String, Object> details(Origin origin, String reason, Holder holder) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("revocation_origin", origin.catalogValue);
        details.put("revocation_reason", origin == Origin.REQUEST ? limited(reason) : null);
        details.put("holder", holder == null ? null : holder.toDetails());
        return details;
    }

    private static String limited(String reason) {
        if (reason == null) {
            return null;
        }
        String withoutControlCharacters = reason.replaceAll("\\p{Cntrl}", " ").strip();
        return withoutControlCharacters.length() > MAX_REASON_LENGTH
                ? withoutControlCharacters.substring(0, MAX_REASON_LENGTH)
                : withoutControlCharacters;
    }
}
