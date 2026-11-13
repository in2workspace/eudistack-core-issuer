package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import java.util.Objects;
import java.util.Optional;

/**
 * Who sends a request to a management API, as far as the volume limit and the idempotency care:
 * the tenant its token was issued for, the organization its attestation represents, whether it is a
 * person or a system, and which one (EUD-269).
 *
 * <p>A person is counted on its own; every system of an organization shares the organization's
 * count. The idempotency keys, instead, belong to each caller, the systems included, so two systems
 * of one organization that send the same key never share a response. A caller the token does not
 * name has no idempotency scope at all: it never shares one with others. The caller is never kept in
 * clear: {@code callerKey} is a pseudonym of it, so neither the counters nor the idempotency records
 * hold personal data.
 *
 * @param tenant                 the tenant of the request, which is the one of its token
 * @param organizationIdentifier the organization of the token (its mandator)
 * @param kind                   person or system
 * @param callerKey              pseudonym of the person or of the system; {@code null} when the token
 *                               does not name it
 */
public record Requester(String tenant, String organizationIdentifier, RequesterKind kind, String callerKey) {

    /** What the persons of an organization the token does not name share in the count. */
    static final String UNIDENTIFIED = "<unidentified>";

    public Requester {
        Objects.requireNonNull(tenant, "tenant");
        Objects.requireNonNull(organizationIdentifier, "organizationIdentifier");
        Objects.requireNonNull(kind, "kind");
        if (tenant.isBlank()) {
            throw new IllegalArgumentException("A requester needs the tenant of its token");
        }
        if (callerKey != null && callerKey.isBlank()) {
            callerKey = null;
        }
    }

    public static Requester system(String tenant, String organizationIdentifier, String callerKey) {
        return new Requester(tenant, organizationIdentifier, RequesterKind.SYSTEM, callerKey);
    }

    public static Requester person(String tenant, String organizationIdentifier, String callerKey) {
        return new Requester(tenant, organizationIdentifier, RequesterKind.PERSON, callerKey);
    }

    /**
     * What is counted together: the organization for its systems, the person (within its
     * organization) for a person. The persons the token does not name share one count.
     */
    public String countingScope() {
        String organization = tenant + "|" + organizationIdentifier;
        if (kind == RequesterKind.SYSTEM) {
            return organization + "|system";
        }
        String person = callerKey != null ? callerKey : UNIDENTIFIED;
        return organization + "|person|" + person;
    }

    /**
     * Whose idempotency keys these are: the caller itself, also when it is one system of the organization.
     * Empty when the token does not name the caller, which must then not use idempotency keys.
     */
    public Optional<String> idempotencyScope() {
        if (callerKey == null) {
            return Optional.empty();
        }
        String kindLabel = kind == RequesterKind.SYSTEM ? "system" : "person";
        return Optional.of(tenant + "|" + organizationIdentifier + "|" + kindLabel + "|" + callerKey);
    }
}
