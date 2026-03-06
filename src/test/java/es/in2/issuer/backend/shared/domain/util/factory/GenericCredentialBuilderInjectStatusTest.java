package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class GenericCredentialBuilderInjectStatusTest {

    private GenericCredentialBuilder builder;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        builder = new GenericCredentialBuilder(
                objectMapper,
                mock(IssuerFactory.class),
                mock(es.in2.issuer.backend.shared.domain.service.AccessTokenService.class)
        );
    }

    @Test
    void injectCredentialStatus_w3cFormat_setsCredentialStatusObject() throws Exception {
        String credentialJson = """
                {"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential"],"credentialSubject":{}}
                """;

        CredentialStatus status = CredentialStatus.builder()
                .id("https://issuer.example/status/42#7")
                .type("BitstringStatusListEntry")
                .statusPurpose("revocation")
                .statusListIndex("7")
                .statusListCredential("https://issuer.example/status/42")
                .build();

        String result = builder.injectCredentialStatus(credentialJson, status, "jwt_vc_json");

        JsonNode node = objectMapper.readTree(result);
        JsonNode cs = node.get("credentialStatus");
        assertNotNull(cs, "credentialStatus should be present");
        assertEquals("https://issuer.example/status/42#7", cs.get("id").asText());
        assertEquals("BitstringStatusListEntry", cs.get("type").asText());
        assertEquals("revocation", cs.get("statusPurpose").asText());
        assertEquals("7", cs.get("statusListIndex").asText());
        assertEquals("https://issuer.example/status/42", cs.get("statusListCredential").asText());
        // Should NOT have "status" key (that's SD-JWT)
        assertNull(node.get("status"));
    }

    @Test
    void injectCredentialStatus_sdJwtFormat_setsStatusListObject() throws Exception {
        String credentialJson = """
                {"vct":"LEARCredentialEmployee","iss":"did:elsi:VATES-12345","sub":"","iat":1000,"exp":2000}
                """;

        CredentialStatus status = CredentialStatus.builder()
                .id("https://issuer.example/token/v1/credentials/status/55#100")
                .type("TokenStatusList")
                .statusPurpose("revocation")
                .statusListIndex("100")
                .statusListCredential("https://issuer.example/token/v1/credentials/status/55")
                .build();

        String result = builder.injectCredentialStatus(credentialJson, status, "dc+sd-jwt");

        JsonNode node = objectMapper.readTree(result);
        // Should NOT have "credentialStatus" (that's W3C)
        assertNull(node.get("credentialStatus"));

        JsonNode statusNode = node.get("status");
        assertNotNull(statusNode, "status should be present");
        JsonNode sl = statusNode.get("status_list");
        assertNotNull(sl, "status_list should be present");
        assertEquals("https://issuer.example/token/v1/credentials/status/55", sl.get("uri").asText());
        assertEquals(100, sl.get("idx").asInt());
    }

    @Test
    void injectCredentialStatus_invalidJson_throwsIllegalState() {
        CredentialStatus status = CredentialStatus.builder()
                .id("id").type("type").statusPurpose("revocation")
                .statusListIndex("0").statusListCredential("url").build();

        assertThrows(IllegalStateException.class,
                () -> builder.injectCredentialStatus("not-json", status, "jwt_vc_json"));
    }
}
