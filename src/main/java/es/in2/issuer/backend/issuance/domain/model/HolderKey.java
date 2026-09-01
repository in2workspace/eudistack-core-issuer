package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public record HolderKey(Map<String, Object> cnf) {

    private static final List<String> CNF_FORMS = List.of("jwk", "kid", "x5c");
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Nimbus-parseable JWKs, allowlisted to asymmetric key types: an issuer signs a credential with
    // this jwk asserted as the holder's, so a symmetric or private key here is not a binding, it's a
    // leaked secret (EUD-168 F1, conv-quality-security-gates.md §2.2).
    private static final Set<KeyType> ALLOWED_KEY_TYPES = Set.of(KeyType.EC, KeyType.OKP, KeyType.RSA);
    private static final Set<Curve> ALLOWED_EC_CURVES = Set.of(Curve.P_256, Curve.P_384, Curve.P_521);
    private static final Set<Curve> ALLOWED_OKP_CURVES = Set.of(Curve.Ed25519, Curve.X25519);
    private static final int MIN_RSA_KEY_SIZE_BITS = 2048;
    // Real-world EC/OKP/RSA public JWKs are well under 1 KB; this only guards against an attacker
    // handing the parser a pathologically large node before any of the checks above run.
    private static final int MAX_JWK_NODE_BYTES = 8192;

    public HolderKey {
        Objects.requireNonNull(cnf, "cnf");
    }

    /** Parses a {@code holder_key} JSON node into a {@link HolderKey}.*/
    public static HolderKey fromJson(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            throw new InvalidHolderKeyException(
                    "holder_key is required for this credential type, in every delivery mode: its schema "
                            + "declares no proof_types_supported, so no wallet key proof will ever "
                            + "arrive and the request is the only source of a holder key");
        }
        if (!node.isObject()) {
            throw new InvalidHolderKeyException("invalid holder_key: expected a JSON object");
        }

        String presentForm = null;
        for (String form : CNF_FORMS) {
            JsonNode value = node.get(form);
            if (value != null && !value.isNull()) {
                if (presentForm != null) {
                    throw new InvalidHolderKeyException(
                            "invalid holder_key: expected exactly one of jwk/kid/x5c");
                }
                presentForm = form;
            }
        }
        if (presentForm == null) {
            throw new InvalidHolderKeyException(
                    "invalid holder_key: expected exactly one of jwk/kid/x5c");
        }

        JsonNode valueNode = node.get(presentForm);
        validateFormShape(presentForm, valueNode);

        Object value = OBJECT_MAPPER.convertValue(valueNode, Object.class);
        return new HolderKey(Map.of(presentForm, value));
    }

    private static void validateFormShape(String form, JsonNode value) {
        switch (form) {
            case "jwk" -> {
                if (!value.isObject() || value.isEmpty()) {
                    throw new InvalidHolderKeyException("invalid holder_key: jwk must be a non-empty JSON object");
                }
                validateJwk(value);
            }
            case "kid" -> {
                if (!value.isTextual() || value.asText().isBlank()) {
                    throw new InvalidHolderKeyException("invalid holder_key: kid must be a non-blank string");
                }
            }
            case "x5c" -> {
                if (!value.isArray() || value.isEmpty()) {
                    throw new InvalidHolderKeyException(
                            "invalid holder_key: x5c must be a non-empty array of certificate strings");
                }
                for (JsonNode cert : value) {
                    if (!cert.isTextual() || cert.asText().isBlank()) {
                        throw new InvalidHolderKeyException("invalid holder_key: x5c entries must be non-blank strings");
                    }
                }
            }
            default -> throw new InvalidHolderKeyException("invalid holder_key: unsupported confirmation form " + form);
        }
    }

    /**
     * Parses the candidate {@code jwk} with Nimbus and rejects anything that is not an asymmetric
     * public key: private key material, symmetric ({@code oct}) keys, non-allowlisted key types, and
     * non-standard curves/sizes. This is the sole point where a caller-supplied {@code holder_key}
     * becomes the {@code cnf} of a signed credential (AD-8), so it is the sole point that has to hold
     * the line (S1).
     */
    private static void validateJwk(JsonNode value) {
        String json;
        try {
            json = OBJECT_MAPPER.writeValueAsString(value);
        } catch (Exception e) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk could not be read");
        }
        if (json.getBytes(StandardCharsets.UTF_8).length > MAX_JWK_NODE_BYTES) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk exceeds the maximum allowed size");
        }

        JWK jwk;
        try {
            jwk = JWK.parse(json);
        } catch (ParseException e) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk is not a well-formed JWK");
        }

        if (jwk.isPrivate()) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk must not contain private key material");
        }
        if (!ALLOWED_KEY_TYPES.contains(jwk.getKeyType())) {
            throw new InvalidHolderKeyException(
                    "invalid holder_key: unsupported jwk key type '" + jwk.getKeyType() + "'");
        }

        switch (jwk) {
            case ECKey ecKey -> {
                if (!ALLOWED_EC_CURVES.contains(ecKey.getCurve())) {
                    throw new InvalidHolderKeyException(
                            "invalid holder_key: unsupported EC curve '" + ecKey.getCurve() + "'");
                }
            }
            case OctetKeyPair okp -> {
                if (!ALLOWED_OKP_CURVES.contains(okp.getCurve())) {
                    throw new InvalidHolderKeyException(
                            "invalid holder_key: unsupported OKP curve '" + okp.getCurve() + "'");
                }
            }
            case RSAKey rsaKey -> {
                if (rsaKey.size() < MIN_RSA_KEY_SIZE_BITS) {
                    throw new InvalidHolderKeyException(
                            "invalid holder_key: RSA key size below the minimum of " + MIN_RSA_KEY_SIZE_BITS + " bits");
                }
            }
            default -> throw new InvalidHolderKeyException(
                    "invalid holder_key: unsupported jwk key type '" + jwk.getKeyType() + "'");
        }
    }
}
