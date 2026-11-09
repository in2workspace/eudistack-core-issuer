package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.BindingType;

import java.util.List;
import java.util.Optional;

/**
 * Lookup port for a credential type's schema profile, keyed by {@code credential_configuration_id}
 * (ADR-110, EUD-168 TD-11). The domain depends only on this interface;
 * {@code CredentialProfileRegistry} (infrastructure) is the sole implementation.
 */
public interface CredentialProfileCatalog {

    CredentialProfile getByConfigurationId(String credentialConfigurationId);

    /**
     * The attributes of the credential type that a catalog entry may point at, as paths into the
     * credential as it is built (before signing). For W3C formats only the paths under
     * {@code credentialSubject} qualify -- the rest of the envelope has no value yet or another one.
     * Objects are traversed; arrays are leaves, as {@link ClaimPath} only holds string segments.
     *
     * @throws IllegalArgumentException if the credential type is not loaded
     */
    List<ClaimPath> attributePaths(String credentialConfigurationId);

    /**
     * Resolves a schema URI to the {@code credential_configuration_id} of the loaded type that
     * publishes it. A type whose file carries no {@code schema_uri} answers to the synthetic URI
     * of {@link #schemaUriOf}; once it carries one, only that one resolves.
     */
    Optional<String> resolveSchemaUri(String schemaUri);

    /**
     * The schema URI of a credential type: the one its file declares or, if it declares none, a
     * synthetic {@code https://registry.eudistack.net/schemas/<credential_configuration_id>}.
     * The synthetic one is a fallback for responses and lookups and must never be stored.
     */
    String schemaUriOf(String credentialConfigurationId);

    /**
     * The holder binding of the credential type: the {@code binding_type} its file declares or, when
     * it declares none, {@link BindingType#KEY} if it declares any
     * {@code cryptographic_binding_methods_supported} or {@code cnf_required: true}, and
     * {@link BindingType#NONE} otherwise.
     *
     * @throws IllegalArgumentException if the credential type is not loaded
     */
    BindingType bindingTypeOf(String credentialConfigurationId);
}
