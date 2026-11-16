package es.in2.issuer.backend.signing.domain.audit;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.signing.domain.model.SigningModality;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the {@code SignatureRequested} entry of one signing attempt. Every attempt is reported, whether
 * it signed an attestation or a status list, and a retry is a new attempt. The certificate travels only
 * as a fingerprint.
 */
public final class SigningAuditEvents {

    /** What was signed, as the catalogue's {@code signed_object}. */
    public enum SignedObject {
        ATTESTATION("Attestation"),
        STATUS_LIST("StatusList");

        private final String catalogValue;

        SignedObject(String catalogValue) {
            this.catalogValue = catalogValue;
        }
    }

    /** How the tenant signs, as the catalogue's {@code modality}. */
    public enum Modality {
        QTSP("Qtsp"),
        OWN_KEY("OwnKey");

        private final String catalogValue;

        Modality(String catalogValue) {
            this.catalogValue = catalogValue;
        }

        public static Modality of(SigningModality modality) {
            return switch (modality) {
                case QTSP -> QTSP;
                case OWN_KEY -> OWN_KEY;
            };
        }
    }

    /** The certificate and algorithm a signature was made with. */
    public record SignatureProof(String algorithm, String certificateHash) {
    }

    private static final int FIRST_ATTEMPT = 1;

    private SigningAuditEvents() {
    }

    public static AuditEntry signed(String resource, SignedObject signedObject, Modality modality,
                                    SignatureProof proof, long durationMs) {
        Map<String, Object> details = baseDetails(signedObject, modality, durationMs);
        details.put("signature_algorithm", proof.algorithm());
        details.put("signing_certificate", proof.certificateHash());
        return AuditEntry.success(AuditEventType.SIGNATURE_REQUESTED, resource, details);
    }

    public static AuditEntry failed(String resource, SignedObject signedObject, Modality modality,
                                    String reason, long durationMs) {
        return AuditEntry.failure(AuditEventType.SIGNATURE_REQUESTED, resource, reason,
                baseDetails(signedObject, modality, durationMs));
    }

    private static Map<String, Object> baseDetails(SignedObject signedObject, Modality modality, long durationMs) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("signed_object", signedObject.catalogValue);
        details.put("modality", modality.catalogValue);
        details.put("attempts", FIRST_ATTEMPT);
        details.put("duration_ms", durationMs);
        return details;
    }
}
