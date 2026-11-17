package es.in2.issuer.backend.statuslist.domain.audit;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the entries of the status list module: the creation of a list and the changes of a position in
 * it. The module is the only owner of these types, so the issuance and revocation flows do not repeat
 * them. A list is the resource of its own events; a position change is about the issuance it belongs to.
 */
public final class StatusListAuditEvents {

    private static final String LIST_URI = "list_uri";
    private static final String OPERATION_RESERVE = "Reserve";
    private static final String OPERATION_RELEASE = "Release";
    private static final String OPERATION_REVOKE = "Revoke";
    private static final String CATALOGUE_FORMAT_TOKEN = "TokenStatusList";
    private static final String CATALOGUE_FORMAT_BITSTRING = "BitstringStatusList";

    private StatusListAuditEvents() {
    }

    public static String listResource(Long listId) {
        return "status-list:" + listId;
    }

    public static String entryResource(String issuanceId) {
        return "status-list-entry:" + issuanceId;
    }

    public static AuditEntry listCreated(Long listId, String listUri, StatusListFormat format, int size) {
        return AuditEntry.success(AuditEventType.STATUS_LIST_CREATED, listResource(listId),
                creationDetails(listUri, format, size));
    }

    public static AuditEntry listCreationFailed(Long listId, String listUri, StatusListFormat format, int size) {
        return AuditEntry.failure(AuditEventType.STATUS_LIST_CREATED, listResource(listId), "SigningFailed",
                creationDetails(listUri, format, size));
    }

    public static AuditEntry reserved(String issuanceId, String listUri, int listIndex) {
        return AuditEntry.success(AuditEventType.STATUS_ENTRY_CHANGED, entryResource(issuanceId),
                entryDetails(OPERATION_RESERVE, listUri, listIndex));
    }

    public static AuditEntry released(String issuanceId, String listUri, int listIndex) {
        return AuditEntry.success(AuditEventType.STATUS_ENTRY_CHANGED, entryResource(issuanceId),
                entryDetails(OPERATION_RELEASE, listUri, listIndex));
    }

    public static AuditEntry revoked(String issuanceId, String listUri, int listIndex) {
        return AuditEntry.success(AuditEventType.STATUS_ENTRY_CHANGED, entryResource(issuanceId),
                entryDetails(OPERATION_REVOKE, listUri, listIndex));
    }

    /** A list signed again and stored, identified by the fingerprint of its new signed form. */
    public static AuditEntry published(Long listId, String listUri, String listHash) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put(LIST_URI, listUri);
        details.put("list_hash", listHash);
        return AuditEntry.success(AuditEventType.STATUS_LIST_PUBLISHED, listResource(listId), details);
    }

    /** {@code reason} is {@code SigningFailed} or {@code PublicationFailed}. */
    public static AuditEntry publicationFailed(Long listId, String listUri, String reason) {
        return AuditEntry.forReason(AuditEventType.STATUS_LIST_PUBLISHED, listResource(listId), reason,
                Map.of(LIST_URI, listUri));
    }

    /** {@code reason} is {@code ListFull} or {@code StatusListUnavailable}. */
    public static AuditEntry reservationFailed(String issuanceId, String reason) {
        return failedChange(issuanceId, OPERATION_RESERVE, reason);
    }

    public static AuditEntry revocationFailed(String issuanceId, String reason) {
        return failedChange(issuanceId, OPERATION_REVOKE, reason);
    }

    private static AuditEntry failedChange(String issuanceId, String operation, String reason) {
        return AuditEntry.failure(AuditEventType.STATUS_ENTRY_CHANGED, entryResource(issuanceId), reason,
                entryDetails(operation, null, null));
    }

    private static Map<String, Object> entryDetails(String operation, String listUri, Integer listIndex) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("operation", operation);
        details.put(LIST_URI, listUri);
        details.put("list_index", listIndex);
        return details;
    }

    private static Map<String, Object> creationDetails(String listUri, StatusListFormat format, int size) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put(LIST_URI, listUri);
        details.put("format", format == StatusListFormat.TOKEN_JWT ? CATALOGUE_FORMAT_TOKEN : CATALOGUE_FORMAT_BITSTRING);
        details.put("size", size);
        return details;
    }
}
