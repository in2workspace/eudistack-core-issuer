package es.in2.issuer.backend.shared.domain.model.port;

public interface IssuerProperties {
    String getIssuerBackendUrl();
    String getIssuerInternalUrl();
    String getIssuerFrontendUrl();
    String getWalletFrontendUrl();
    String getVerifierUrl();
    String getVerifierInternalUrl();
    String getDefaultLang();
    String getAdminOrganizationId();
    String getSysTenant();
    String getCredentialSubjectDidKey();
    String getManagementTokenOrgIdJsonPath();
    String getManagementTokenAdminPowerFunction();
    String getManagementTokenAdminPowerAction();

    /**
     * Checks whether the given issuer URL belongs to the verifier.
     * In multi-tenant mode (subdomain routing), the verifier sets iss dynamically
     * per tenant (e.g. cgcom.127.0.0.1.nip.io:4444 vs altia.127.0.0.1.nip.io:4444).
     * This method compares the base origin (scheme + base domain + port) so that
     * any tenant subdomain is accepted. Signature verification against the verifier's
     * JWKS provides the actual cryptographic security.
     */
    boolean isVerifierIssuer(String issuer);

    /**
     * Checks whether the given issuer URL belongs to the issuer backend itself.
     * In multi-tenant mode (subdomain routing), the issuer sets iss dynamically
     * per tenant. This method compares the base origin (scheme + base domain + port)
     * so that any tenant subdomain is accepted.
     */
    boolean isIssuerBackendIssuer(String issuer);
}
