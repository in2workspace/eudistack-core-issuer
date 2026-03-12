package es.in2.issuer.backend.shared.domain.model.port;

public interface IssuerProperties {
    String getIssuerBackendUrl();
    String getIssuerInternalUrl();
    String getIssuerFrontendUrl();
    String getWalletFrontendUrl();
    String getVerifierUrl();
    String getDefaultLang();
    String getAdminOrganizationId();
    String getSysTenant();
    String getCredentialSubjectDidKey();
    String getJwtCredential();
    String getManagementTokenOrgIdJsonPath();
    String getManagementTokenAdminPowerFunction();
    String getManagementTokenAdminPowerAction();
}
