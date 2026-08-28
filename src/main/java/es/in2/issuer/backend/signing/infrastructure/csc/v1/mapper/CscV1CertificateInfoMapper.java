package es.in2.issuer.backend.signing.infrastructure.csc.v1.mapper;

import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.CertificateQualificationUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@Component
public class CscV1CertificateInfoMapper {

    public CertificateInfo map(Map<String, Object> response) {
        if (response == null) {
            throw new IllegalStateException("CSC credentials/info response is null");
        }

        Map<String, Object> key = castMap(response.get("key"), "key");
        String keyStatus = (String) key.get("status");
        if (keyStatus != null && !Set.of("enabled", "valid").contains(keyStatus.toLowerCase())) {
            throw new IllegalStateException("Signing key is not enabled: " + keyStatus);
        }

        List<String> keyAlgorithms = castStringList(key.get("algo"), "key.algo");
        if (keyAlgorithms.isEmpty()) {
            throw new IllegalStateException("No signing algorithm returned by QTSP");
        }

        Integer keyLength = (Integer) key.get("len");

        Map<String, Object> cert = castMap(response.get("cert"), "cert");
        String certStatus = (String) cert.get("status");
        if (certStatus != null && !"valid".equalsIgnoreCase(certStatus)) {
            throw new IllegalStateException("Certificate is not valid: " + certStatus);
        }

        List<String> certificates = castStringList(cert.get("certificates"), "cert.certificates");
        if (certificates.isEmpty()) {
            throw new IllegalStateException("No certificate chain returned by QTSP");
        }

        String subjectDN   = (String) cert.get("subjectDN");
        String issuerDN    = (String) cert.get("issuerDN");
        String serialNumber = (String) cert.get("serialNumber");
        String validFrom   = (String) cert.get("validFrom");
        String validTo     = (String) cert.get("validTo");

        if (subjectDN == null) {
            try {
                byte[] der = Base64.getDecoder().decode(certificates.get(0));
                X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(der));
                subjectDN    = x509.getSubjectX500Principal().getName();
                issuerDN     = x509.getIssuerX500Principal().getName();
                serialNumber = x509.getSerialNumber().toString(16).toUpperCase();
            } catch (Exception e) {
                log.warn("Could not extract cert metadata from X.509 certificate: {}", e.getMessage());
            }
        }

        return new CertificateInfo(
                certificates,
                issuerDN,
                subjectDN,
                serialNumber,
                validFrom,
                validTo,
                keyAlgorithms,
                keyLength,
                CertificateQualificationUtils.isQualifiedSeal(certificates)
        );
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value, String field) {
        if (value == null) {
            throw new IllegalStateException("Missing '" + field + "' section in CSC response");
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<String> castStringList(Object value, String field) {
        if (value == null) {
            throw new IllegalStateException("Missing '" + field + "' in CSC response");
        }
        return (List<String>) value;
    }
}
