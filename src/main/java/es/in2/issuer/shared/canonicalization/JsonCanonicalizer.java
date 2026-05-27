package es.in2.issuer.shared.canonicalization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import static com.fasterxml.jackson.databind.MapperFeature.SORT_PROPERTIES_ALPHABETICALLY;


public final class JsonCanonicalizer {

    private static final ObjectMapper CANONICAL_MAPPER = JsonMapper.builder()
            .enable(SORT_PROPERTIES_ALPHABETICALLY)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .configure(SerializationFeature.INDENT_OUTPUT, false)
            .build();

    private JsonCanonicalizer() {
    }

    public static String canonicalize(String json) throws JsonProcessingException {
        Object parsed = CANONICAL_MAPPER.readValue(json, Object.class);
        return CANONICAL_MAPPER.writeValueAsString(parsed);
    }


    public static String sha256(String json) {
        try {
            String canonical = json == null ? "" : canonicalize(json);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(canonical.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (JsonProcessingException e) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(json.getBytes(StandardCharsets.UTF_8));
                return HexFormat.of().formatHex(digest);
            } catch (NoSuchAlgorithmException nsa) {
                throw new IllegalStateException("SHA-256 not available", nsa);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}



