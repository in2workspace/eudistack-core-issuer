package es.in2.issuer.backend.signing.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class JadesHeaderBuilderServiceImpl implements JadesHeaderBuilderService {

    private final ObjectMapper objectMapper;

    @Override
    public String buildHeader(CertificateInfo certInfo, JadesProfile profile, String typ) {
        try {
            if (certInfo == null) throw new IllegalArgumentException("certInfo is required");
            if (profile == null) throw new IllegalArgumentException("profile is required");

            Map<String, Object> header = new HashMap<>();

            String sealLevel = certInfo.qualifiedSeal() ? "QSeal cualificado (QCP-l-qscd, FR-17)" : "AdESeal (FR-11/FR-12)";
            log.info("Seal level: {}", sealLevel);

            String jwtAlg = mapOidToJwtAlg(certInfo.keyAlgorithms());
            header.put("alg", jwtAlg);

            header.put("typ", typ != null ? typ : "JWT");

            header.put("x5c", certInfo.certificates());

            applyProfileSpecificFields(header, profile);

            return objectMapper.writeValueAsString(header);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build JAdES header", e);
        }
    }

    private void applyProfileSpecificFields(Map<String, Object> header, JadesProfile profile) {
        switch (profile) {
            case JADES_B_T -> header.put("sigT", Instant.now().toString());
            case JADES_B_LT, JADES_B_LTA -> throw new IllegalStateException(profile + " not yet supported");
            default -> log.info("No additional header fields needed for profile {}", profile);
        }
    }

    private String mapOidToJwtAlg(List<String> oids) {
        if (oids == null || oids.isEmpty()) {
            throw new IllegalArgumentException("No signing algorithm found in certificate info");
        }

        return switch (oids.getFirst()) {
            case "1.2.840.10045.4.3.2" -> "ES256";
            case "1.2.840.10045.4.3.3" -> "ES384";
            case "1.2.840.10045.4.3.4" -> "ES512";
            case "1.2.840.113549.1.1.11" -> "RS256";
            case "1.2.840.113549.1.1.12" -> "RS384";
            case "1.2.840.113549.1.1.13" -> "RS512";
            case "1.2.840.113549.1.1.10" -> "PS256";
            // Generic key-algorithm OIDs (e.g. Vintegris reports rsaEncryption /
            // id-ecPublicKey in credentials/info key.algo instead of a concrete
            // signature OID). Since signing always uses a SHA-256 digest, map
            // these to the SHA-256 JWS algorithm for the matching key type.
            case "1.2.840.113549.1.1.1" -> "RS256"; // rsaEncryption
            case "1.2.840.10045.2.1" -> "ES256";    // id-ecPublicKey
            default -> throw new IllegalArgumentException("Unsupported OID: " + oids.getFirst());
        };
    }
}