package es.in2.issuer.backend.signing.domain.model.port;

public interface SignerConfig {
    String getOrganizationIdentifier();
    String getOrganization();
    String getCountry();
    String getCommonName();
    String getSerialNumber();
}
