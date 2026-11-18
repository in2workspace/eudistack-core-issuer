package es.in2.issuer.backend.shared.domain.model.audit;

/**
 * Logical producers that share the Issuer outbox. The status list and signing modules run inside the
 * Issuer process but own their own event types, so each stamps its events with its own {@code source}.
 */
public final class AuditSource {

    public static final String ISSUER = "issuer";
    public static final String STATUS_LISTS = "status-lists";
    public static final String SIGNING = "signing";

    private AuditSource() {
    }
}
