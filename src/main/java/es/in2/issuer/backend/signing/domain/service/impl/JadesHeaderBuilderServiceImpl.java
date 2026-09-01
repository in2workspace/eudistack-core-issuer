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
import java.util.ArrayList;
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

            header.put("x5c", withoutTrustAnchor(certInfo.certificates()));

            applyProfileSpecificFields(header, profile);

            return objectMapper.writeValueAsString(header);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build JAdES header", e);
        }
    }

    /**
     * HAIP §6.1 and §6.1.1 both require that the trust anchor's certificate is NOT carried in
     * the x5c header — of the SD-JWT VC and of the Status List Token alike. A Verifier anchors
     * trust in its own list of roots; a root that travels with the signature proves nothing,
     * because whoever forged the leaf could forge the root next to it.
     *
     * <p>The QTSP answers {@code credentials/info} with the full chain, root included, so the
     * self-signed anchor is dropped here. The leaf is never dropped, even when it is itself
     * self-signed: HAIP forbids that too, but emitting an empty x5c would hide the
     * misconfiguration behind an unverifiable signature instead of surfacing it.
     */
    private List<String> withoutTrustAnchor(List<String> chain) {
        if (chain == null || chain.size() < 2) {
            return chain;
        }

        List<String> trimmed = new ArrayList<>(chain);
        while (trimmed.size() > 1 && isSelfSigned(trimmed.getLast())) {
            trimmed.removeLast();
        }

        if (trimmed.size() != chain.size()) {
            log.debug("Dropped {} trust anchor certificate(s) from x5c (HAIP 6.1/6.1.1)",
                    chain.size() - trimmed.size());
        }
        return trimmed;
    }

    /**
     * A certificate is the anchor when it signs itself. Subject/issuer equality alone is not
     * enough — a cross-signed intermediate can carry the same DN — so the self-signature is
     * verified. An entry that cannot be parsed is treated as not-an-anchor: leaving an extra
     * certificate in x5c degrades conformance, dropping a needed one breaks verification.
     */
    private boolean isSelfSigned(String base64Certificate) {
        try {
            byte[] der = Base64.getDecoder().decode(base64Certificate);
            X509Certificate certificate = (X509Certificate) CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));

            if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                return false;
            }
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception e) {
            log.warn("Could not determine whether an x5c entry is the trust anchor; keeping it. reason={}",
                    e.getMessage());
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