package es.in2.issuer.backend.signing.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
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

            header.put("x5c", trimSelfSignedRoot(certInfo.certificates()));

            applyProfileSpecificFields(header, profile);

            return objectMapper.writeValueAsString(header);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build JAdES header", e);
        }
    }

    /**
     * HAIP §6.1 forbids a conformant issuer from including the self-signed root certificate in
     * x5c - the relying party is expected to already trust it out-of-band. The QTSP's
     * {@code credentials/info} response (requested with the full chain) includes it regardless
     * - {@link CertificateInfo#certificates()} is the list exactly as the QTSP returned it, with
     * no local filtering. Trimmed here, once, so both credentials and status list tokens (they
     * share this one header-building code path) stop publishing it.
     */
    private List<String> trimSelfSignedRoot(List<String> certificates) {
        if (certificates == null || certificates.size() < 2) {
            // Nothing to trim: no chain, or a lone leaf with no separate root to strip.
            return certificates;
        }
        String last = certificates.getLast();
        if (isSelfSigned(last)) {
            return certificates.subList(0, certificates.size() - 1);
        }
        return certificates;
    }

    private boolean isSelfSigned(String base64DerCertificate) {
        try {
            byte[] der = Base64.getDecoder().decode(base64DerCertificate);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
            if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                return false;
            }
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            // Fail closed on "don't trim" - an unparseable trailing cert is left in the chain
            // rather than risking a mangled x5c from misclassifying it.
            log.warn("Could not determine whether the trailing x5c certificate is self-signed - " +
                    "leaving it in the chain as-is: {}", e.getMessage());
            return false;
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