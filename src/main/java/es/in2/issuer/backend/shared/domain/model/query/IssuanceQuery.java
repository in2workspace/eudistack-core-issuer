package es.in2.issuer.backend.shared.domain.model.query;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.util.SubjectSearch;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A page of the listing or of the search of issuance processes (EUD-255 FR-03, FR-04, FR-05, FR-10, FR-11),
 * already checked for shape: the filters, the page size and, from the second page on, the cursor.
 *
 * @param lifeCycleStatuses        states to keep; empty means every state
 * @param credentialConfigurationId catalogue entry to keep, or {@code null}
 * @param tenant                   tenant to keep, only from the platform tenant, or {@code null}
 * @param limit                    processes per page, 1 to {@link #MAX_LIMIT}
 * @param cursor                   where the page starts, or {@code null} for the first page
 * @param subject                  text searched in the subject, as the request gave it, or {@code null} for no
 *                                 search by name; it is compared in the form of {@link SubjectSearch} (AD-9)
 * @param identifier               the search by business identifier, or {@code null}; it reaches the persistence
 *                                 and the cursor only fingerprinted (AD-4, AD-5)
 */
public record IssuanceQuery(
        Set<CredentialStatusEnum> lifeCycleStatuses,
        String credentialConfigurationId,
        String tenant,
        int limit,
        PageCursor cursor,
        String subject,
        SearchIdentifierCriterion identifier
) {
    public static final int DEFAULT_LIMIT = 50;
    public static final int MAX_LIMIT = 200;

    public IssuanceQuery {
        lifeCycleStatuses = lifeCycleStatuses == null || lifeCycleStatuses.isEmpty()
                ? Set.of()
                : Set.copyOf(EnumSet.copyOf(lifeCycleStatuses));
        if (limit < 1 || limit > MAX_LIMIT) {
            throw new IllegalArgumentException("limit out of range");
        }
        if (subject != null && identifier != null) {
            throw new IllegalArgumentException("A search is by name or by identifier, not both");
        }
    }

    /** A page of the listing or of the search by name. */
    public IssuanceQuery(Set<CredentialStatusEnum> lifeCycleStatuses, String credentialConfigurationId, String tenant,
                         int limit, PageCursor cursor, String subject) {
        this(lifeCycleStatuses, credentialConfigurationId, tenant, limit, cursor, subject, null);
    }

    /** A page of the listing, with no search by name. */
    public IssuanceQuery(Set<CredentialStatusEnum> lifeCycleStatuses, String credentialConfigurationId, String tenant,
                         int limit, PageCursor cursor) {
        this(lifeCycleStatuses, credentialConfigurationId, tenant, limit, cursor, null, null);
    }

    /** The same query, searching by the fingerprint of its identifier instead of its value. */
    public IssuanceQuery withIdentifierFingerprint(byte[] fingerprint) {
        if (identifier == null) {
            throw new IllegalStateException("The query does not search by identifier");
        }
        return new IssuanceQuery(lifeCycleStatuses, credentialConfigurationId, tenant, limit, cursor, subject,
                identifier.fingerprinted(fingerprint));
    }

    /** Without the text searched, which is personal data and may only reach the audit trail (AD-5). */
    @Override
    public String toString() {
        return "IssuanceQuery[lifeCycleStatuses=" + lifeCycleStatuses
                + ", credentialConfigurationId=" + credentialConfigurationId
                + ", tenant=" + tenant + ", limit=" + limit + ", cursor=" + (cursor != null)
                + ", subject=" + (subject == null ? "none" : "<redacted>")
                + ", identifier=" + identifier + "]";
    }

    /** The first page with no filters. */
    public static IssuanceQuery firstPage() {
        return new IssuanceQuery(Set.of(), null, null, DEFAULT_LIMIT, null);
    }

    /**
     * The filters the request gave, by their parameter names, for the trace of the query (EUD-255 AD-7).
     * A filter not given is left out; the page size and the cursor are not filters.
     */
    public Map<String, Object> filters() {
        Map<String, Object> filters = new LinkedHashMap<>();
        if (!lifeCycleStatuses.isEmpty()) {
            filters.put("life_cycle_status", lifeCycleStatuses.stream().map(Enum::name).sorted().toList());
        }
        if (credentialConfigurationId != null) {
            filters.put("credential_configuration_id", credentialConfigurationId);
        }
        if (tenant != null) {
            filters.put("tenant", tenant);
        }
        if (subject != null) {
            filters.put("subject", subject);
        }
        if (identifier != null) {
            filters.put("identifier_type", identifier.type());
            if (identifier.value() != null) {
                filters.put("identifier", identifier.value());
            }
        }
        return filters;
    }

    /**
     * A digest of the filters, which the cursor carries so that it is only accepted with the filters
     * it was given for. The page size is not part of it: a client may change it between pages. The text of
     * a search by name counts in its compared form, and only when there is one, so the cursors of the
     * listing do not change. An identifier counts by its fingerprint, never by its value: an unkeyed hash of a
     * DNI in a cursor could be reversed by trying them all.
     *
     * @throws IllegalStateException for a search by identifier that has not been fingerprinted yet
     */
    public String filterDigest() {
        String states = lifeCycleStatuses.stream()
                .map(Enum::name)
                .sorted()
                .collect(Collectors.joining(","));
        String canonical = "life_cycle_status=" + states
                + "\ncredential_configuration_id=" + Objects.toString(credentialConfigurationId, "")
                + "\ntenant=" + Objects.toString(tenant, "")
                + (subject == null ? "" : "\nsubject=" + SubjectSearch.normalize(subject))
                + (identifier == null ? "" : "\nidentifier_type=" + identifier.type()
                        + "\nidentifier=" + identifier.fingerprintText());
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOf(hash, 16));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
