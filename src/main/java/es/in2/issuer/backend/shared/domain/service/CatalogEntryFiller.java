package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * Completes a catalog entry that has not been configured yet from its credential type file
 * (EUD-266 D12, D13): the schema URI the file declares, the schema's delivery-mode ceiling, and the
 * validity and subject the type used to hard-code. Shared by the start-up backfill and by the
 * fill-on-read of rows seeded while the issuer was already running.
 *
 * <p>Idempotent: an entry that is already complete comes back equal, so a caller detects "nothing to
 * fill" with {@code equals}. Validity and subject are filled together, and only while the validity is
 * missing: an entry saved without a subject has an empty subject and never goes back to the file (D9).
 */
@Service
@RequiredArgsConstructor
public class CatalogEntryFiller {

    private static final String DEFAULT_SEPARATOR = " ";

    private final CredentialProfileCatalog credentialProfileCatalog;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;

    /** Returns {@code entry} unchanged when its credential type file is not loaded. */
    public CatalogEntry fill(CatalogEntry entry) {
        CredentialProfile profile = credentialProfileCatalog.getByConfigurationId(entry.credentialConfigurationId());
        if (profile == null) {
            return entry;
        }

        String schemaUri = entry.schemaUri() == null && profile.schemaUri() != null && !profile.schemaUri().isBlank()
                ? profile.schemaUri()
                : entry.schemaUri();
        Set<DeliveryMode> deliveryModes = entry.deliveryModes() != null
                ? entry.deliveryModes()
                : schemaDeliveryCeiling.resolveEligibleModes(entry.credentialConfigurationId());

        CatalogEntry.Validity validity = entry.validity();
        CatalogEntry.Subject subject = entry.subject();
        if (validity == null) {
            validity = validityOf(profile);
            subject = subjectOf(profile);
        }

        return new CatalogEntry(entry.credentialConfigurationId(), schemaUri, entry.enabled(), deliveryModes,
                validity, subject, entry.searchIdentifiers(), entry.version(), entry.created(), entry.updated());
    }

    /** The registry only loads types that state their {@code validity_days} (at least 1). */
    @SuppressWarnings("deprecation")
    private static CatalogEntry.Validity validityOf(CredentialProfile profile) {
        return new CatalogEntry.Validity(profile.validityDays(), false, null);
    }

    @SuppressWarnings("deprecation")
    private static CatalogEntry.Subject subjectOf(CredentialProfile profile) {
        var fields = SubjectPathConverter.toClaimPaths(profile);
        if (fields.isEmpty()) {
            return null;
        }
        String separator = profile.subjectExtraction().separator();
        return new CatalogEntry.Subject(fields, separator != null ? separator : DEFAULT_SEPARATOR);
    }
}
