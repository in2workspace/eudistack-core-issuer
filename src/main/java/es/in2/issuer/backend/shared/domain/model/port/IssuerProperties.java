package es.in2.issuer.backend.shared.domain.model.port;

public interface IssuerProperties {
    String getIssuerBackendUrl();
    String getIssuerFrontendUrl();
    String getWalletFrontendUrl();
    String getKnowledgebaseWalletUrl();
    String getVerifierUrl();
    String getDefaultLang();
    String getAdminOrganizationId();
    String getSysTenant();
    String getCredentialSubjectDidKey();
    String getJwtCredential();
}
