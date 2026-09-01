package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record HolderKey(Map<String, Object> cnf) {

    private static final List<String> CNF_FORMS = List.of("jwk", "kid", "x5c");
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Nimbus-parseable JWKs, allowlisted to exactly the key type and curve this issuer can actually
    // verify and bind: ES256 is the only algorithm conv-quality-security-gates.md §4.2/§6.1
    // approves, and DidKeyDerivation only knows how to turn a P-256 point into a did:key. Widening
    // this (EUD-168 code-review, F2a) accepted curves/key types the rest of the pipeline could not
    // back up -- an OKP or RSA jwk would pass validation here and then silently fail did:key
    // derivation downstream, which is worse than rejecting it here. A symmetric or private key here
    // is not a binding, it's a leaked secret (EUD-168 F1, conv-quality-security-gates.md §2.2).
    private static final KeyType ALLOWED_KEY_TYPE = KeyType.EC;
    private static final Curve ALLOWED_EC_CURVE = Curve.P_256;
    // Real-world EC P-256 public JWKs are well under 1 KB; this only guards against an attacker
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
        Object value = "jwk".equals(presentForm)
                ? validateAndCanonicalizeJwk(valueNode)
                : validateNonJwkFormShape(presentForm, valueNode);
        return new HolderKey(Map.of(presentForm, value));
    }

    /**
     * {@code true} when this node is a {@code jwk}-shaped {@code holder_key} -- the only form AD-8
     * exempt types accept (F1a): {@code kid} is a pointer the issuer cannot resolve without a wallet,
     * and {@code x5c} an unparsed certificate chain, so neither carries key material this path can
     * validate or bind to {@code mandatee.id}. Checked at the call site rather than inside
     * {@link #fromJson}, which stays a general-purpose RFC 7800 parser for the key-proof path where
     * all three forms remain meaningful.
     */
    public boolean isJwkForm() {
        return cnf.containsKey("jwk");
    }

    private static Object validateNonJwkFormShape(String form, JsonNode value) {
        switch (form) {
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
        return OBJECT_MAPPER.convertValue(value, Object.class);
    }

    /**
     * Parses the candidate {@code jwk} with Nimbus and rejects anything that is not an EC P-256
     * public key: private key material, symmetric ({@code oct}) keys, any other key type or curve.
     * This is the sole point where a caller-supplied {@code holder_key} becomes the {@code cnf} of a
     * signed credential (AD-8), so it is the sole point that has to hold the line (S1).
     *
     * <p>Returns Nimbus's own canonical serialization ({@link JWK#toJSONObject()}), not the raw
     * request node (F1b): Nimbus silently accepts and preserves unknown members alongside a
     * structurally valid JWK, and the raw node was what used to reach the signed credential.
     */
    private static Map<String, Object> validateAndCanonicalizeJwk(JsonNode value) {
        if (!value.isObject() || value.isEmpty()) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk must be a non-empty JSON object");
        }
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
        if (!ALLOWED_KEY_TYPE.equals(jwk.getKeyType())) {
            throw new InvalidHolderKeyException(
                    "invalid holder_key: unsupported jwk key type '" + jwk.getKeyType() + "'");
        }
        if (!(jwk instanceof ECKey ecKey) || !ALLOWED_EC_CURVE.equals(ecKey.getCurve())) {
            throw new InvalidHolderKeyException(
                    "invalid holder_key: unsupported EC curve, only '" + ALLOWED_EC_CURVE + "' is accepted");
        }

        return new LinkedHashMap<>(jwk.toJSONObject());
    }
}
