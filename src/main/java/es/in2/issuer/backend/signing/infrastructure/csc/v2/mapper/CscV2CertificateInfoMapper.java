package es.in2.issuer.backend.signing.infrastructure.csc.v2.mapper;

import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.CertificateQualificationUtils;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class CscV2CertificateInfoMapper {

    public CertificateInfo map(Map<String, Object> response) {
        if (response == null) {
            throw new IllegalStateException("CSC credentials/info response is null");
        }

        Map<String, Object> key = castMap(response.get("key"), "key");
        String keyStatus = (String) key.get("status");
        if (!Set.of("enabled", "valid").contains(keyStatus.toLowerCase())) {
            throw new IllegalStateException("Signing key is not enabled: " + keyStatus);
        }

        List<String> keyAlgorithms = castStringList(key.get("algo"), "key.algo");
        if (keyAlgorithms.isEmpty()) {
            throw new IllegalStateException("No signing algorithm returned by QTSP");
        }

        Integer keyLength = (Integer) key.get("len");

        Map<String, Object> cert = castMap(response.get("cert"), "cert");
        String certStatus = (String) cert.get("status");
        if (!"valid".equalsIgnoreCase(certStatus)) {
            throw new IllegalStateException("Certificate is not valid: " + certStatus);
        }

        List<String> certificates = castStringList(cert.get("certificates"), "cert.certificates");
        if (certificates.isEmpty()) {
            throw new IllegalStateException("No certificate chain returned by QTSP");
        }

        return new CertificateInfo(
                certificates,
                (String) cert.get("issuerDN"),
                (String) cert.get("subjectDN"),
                (String) cert.get("serialNumber"),
                (String) cert.get("validFrom"),
                (String) cert.get("validTo"),
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
