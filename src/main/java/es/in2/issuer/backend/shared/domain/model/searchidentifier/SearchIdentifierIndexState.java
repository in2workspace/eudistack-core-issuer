package es.in2.issuer.backend.shared.domain.model.searchidentifier;

import java.util.Objects;

/**
 * What the fingerprints of the processes of one catalog entry were last computed with (EUD-267): its search
 * identifiers and the tenant key. When either differs from what the entry declares now, or there is no state yet
 * (the initial load), the processes of the entry are fingerprinted again in the background.
 *
 * @param credentialConfigurationId the catalog entry
 * @param searchIdentifiers         the identifiers indexed, as a canonical signature (see
 *                                  {@link es.in2.issuer.backend.shared.domain.service.SearchIdentifierIndexer#signatureOf})
 * @param keyId                     {@link SearchIdentifierFingerprinter#keyId} of the key used; {@code null} when the
 *                                  entry declared no identifiers
 */
public record SearchIdentifierIndexState(String credentialConfigurationId, String searchIdentifiers, String keyId) {

    public SearchIdentifierIndexState {
        Objects.requireNonNull(credentialConfigurationId, "credentialConfigurationId");
        Objects.requireNonNull(searchIdentifiers, "searchIdentifiers");
    }
}
