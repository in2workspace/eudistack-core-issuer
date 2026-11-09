package es.in2.issuer.backend.shared.domain.model.catalog;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * A credential type of a tenant's catalog together with the configuration the tenant gave it.
 *
 * <p>Nullable members describe a row that is not fully configured yet:
 * <ul>
 *   <li>{@code schemaUri}: {@code null} while the credential type file carries no real schema URI.
 *       The synthetic fallback is never stored (see {@code CredentialProfileCatalog#schemaUriOf}).</li>
 *   <li>{@code deliveryModes}: {@code null} = row not filled yet; empty = an explicit empty list,
 *       which only a disabled entry may hold.</li>
 *   <li>{@code validity}: {@code null} = row not filled yet. It is the marker used to tell an
 *       unfilled row from an entry saved without a subject.</li>
 *   <li>{@code subject}: {@code null} = no subject, whose value is the empty string.</li>
 * </ul>
 * {@code created} and {@code updated} are {@code null} on an entry that has not been persisted.
 */
public record CatalogEntry(
        String credentialConfigurationId,
        String schemaUri,
        boolean enabled,
        Set<DeliveryMode> deliveryModes,
        Validity validity,
        Subject subject,
        List<SearchIdentifier> searchIdentifiers,
        long version,
        Instant created,
        Instant updated
) {

    public CatalogEntry {
        deliveryModes = deliveryModes == null ? null : Set.copyOf(deliveryModes);
        searchIdentifiers = searchIdentifiers == null ? List.of() : List.copyOf(searchIdentifiers);
    }

    /** {@code maxDays} is {@code null} when the requester cannot set the dates. */
    public record Validity(int defaultDays, boolean requesterCanSetDates, Integer maxDays) {
    }

    public record Subject(List<ClaimPath> fields, String separator) {

        public Subject {
            fields = List.copyOf(fields);
        }
    }

    public record SearchIdentifier(String name, ClaimPath field) {
    }

    /** {@code true} once the validity and the delivery modes have been materialised. */
    public boolean isFilled() {
        return validity != null && deliveryModes != null;
    }

    public CatalogEntry withEnabled(boolean newEnabled) {
        return new CatalogEntry(credentialConfigurationId, schemaUri, newEnabled, deliveryModes, validity, subject,
                searchIdentifiers, version, created, updated);
    }

    public CatalogEntry withDeliveryModes(Set<DeliveryMode> newDeliveryModes) {
        return new CatalogEntry(credentialConfigurationId, schemaUri, enabled, newDeliveryModes, validity, subject,
                searchIdentifiers, version, created, updated);
    }

    public CatalogEntry withSchemaUri(String newSchemaUri) {
        return new CatalogEntry(credentialConfigurationId, newSchemaUri, enabled, deliveryModes, validity, subject,
                searchIdentifiers, version, created, updated);
    }
}
