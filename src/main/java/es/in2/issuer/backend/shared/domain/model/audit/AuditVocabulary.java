package es.in2.issuer.backend.shared.domain.model.audit;

/** Actions and reasons of the catalogue that more than one event type shares. */
final class AuditVocabulary {

    static final String ACTION_ISSUE = "Issue";

    static final String POLICY_DENIED = "PolicyDenied";
    static final String SIGNING_FAILED = "SigningFailed";
    static final String STATUS_LIST_UNAVAILABLE = "StatusListUnavailable";

    private AuditVocabulary() {
    }
}
