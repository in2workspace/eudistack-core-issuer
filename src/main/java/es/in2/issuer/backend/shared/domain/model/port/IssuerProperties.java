package es.in2.issuer.backend.shared.domain.model.port;

/**
 * Port for non-URL application settings.
 *
 * <p>Public URL resolution lives in
 * {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver} — public URLs
 * are derived from the current {@code ServerWebExchange}, never from a
 * static property (EUDI-017). Internal intra-VPC URLs are still exposed
 * here because callers without a request scope (health indicator,
 * UrlResolver itself) need them.
 */
public interface IssuerProperties {
    String getIssuerInternalUrl();
    String getVerifierInternalUrl();
    String getDefaultLang();
    String getSysTenant();
    String getManagementTokenOrgIdJsonPath();
    String getManagementTokenAdminPowerFunction();
    String getManagementTokenAdminPowerAction();
}
