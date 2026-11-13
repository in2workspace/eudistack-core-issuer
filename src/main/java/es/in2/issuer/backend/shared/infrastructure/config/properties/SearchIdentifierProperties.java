package es.in2.issuer.backend.shared.infrastructure.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;

/**
 * The secret key of each tenant, for the fingerprints of the search identifiers (EUD-267; §6 of the EUD-254 design).
 *
 * @param keyParameter  the Parameter Store name of a tenant's key, with {@code {tenant}} where the tenant goes, for
 *                      example {@code /eudistack/dev/config/tenants/{tenant}/issuer/search-identifier-key}. The
 *                      parameter is a {@code SecureString} with 32 random bytes in base64. Empty: no key can be read,
 *                      and only an issuance of a type with search identifiers fails
 * @param endpoint      Parameter Store endpoint, only for emulators such as LocalStack
 * @param localKeySeed  the seed from which the {@code local} profile derives a key per tenant; only allowed with that
 *                      profile, the issuer does not start with it otherwise
 */
@ConfigurationProperties(prefix = "issuer.search-identifiers")
public record SearchIdentifierProperties(String keyParameter, URI endpoint, String localKeySeed) {

    /** Where the tenant goes in {@link #keyParameter}. */
    public static final String TENANT_PLACEHOLDER = "{tenant}";
}
