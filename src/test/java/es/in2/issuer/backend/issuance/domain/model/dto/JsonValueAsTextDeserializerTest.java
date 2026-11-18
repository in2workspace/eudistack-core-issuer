package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class JsonValueAsTextDeserializerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static IssuanceRequest read(String fields) throws Exception {
        return MAPPER.readValue("{\"credential_configuration_id\": \"doctorid.sd.1\", \"payload\": {}, "
                + "\"email\": \"jane.doe@example.org\", " + fields + "}", IssuanceRequest.class);
    }

    @Test
    void aStringIsReadAsItsText() throws Exception {
        IssuanceRequest request = read("\"delivery\": \"email\", \"grant_type\": \"authorization_code\"");

        assertEquals("email", request.delivery());
        assertEquals("authorization_code", request.grantType());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "[\"email\",\"ui\"]   | [\"email\",\"ui\"]",
            "[]                   | []",
            "5                    | 5",
            "true                 | true",
            "{\"mode\":\"email\"} | {\"mode\":\"email\"}"
    })
    void anyOtherValueIsReadAsItsJsonText(String json, String expected) throws Exception {
        IssuanceRequest request = read("\"delivery\": " + json + ", \"grant_type\": " + json);

        assertEquals(expected, request.delivery());
        assertEquals(expected, request.grantType());
    }

    @Test
    void jsonNullStaysNull() throws Exception {
        IssuanceRequest request = read("\"delivery\": null, \"grant_type\": null");

        assertNull(request.delivery());
        assertNull(request.grantType());
    }
}
