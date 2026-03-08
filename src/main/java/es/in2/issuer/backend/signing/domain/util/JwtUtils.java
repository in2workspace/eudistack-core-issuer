package es.in2.issuer.backend.signing.domain.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Component
@Slf4j
public class JwtUtils {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public String decodePayload(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("invalid JWT");
        }

        byte[] decodedBytes = Base64.getUrlDecoder().decode(parts[1]);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    public boolean areJsonsEqual(String json1, String json2) {
        try {
            Map<String, Object> map1 = objectMapper.readValue(json1, Map.class);
            Map<String, Object> map2 = objectMapper.readValue(json2, Map.class);

            return map1.equals(map2);
        } catch (Exception e) {
            log.error("Error comparing JSONs", e);
            return false;
        }
    }
}
