package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-268 (EUD-254 contract): {@code delivery} and {@code grant_type} are not checked on their shape at
 * the DTO boundary. Any value other than the admitted ones is the contract's {@code invalid_delivery_mode}
 * or {@code invalid_grant_type}, decided by the workflow -- a shape constraint here would turn it into a
 * {@code BAD_REQUEST}. The values sent never reach a log line or a metric tag (IssuanceWorkflowImplTest).
 */
class IssuanceRequestValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    private IssuanceRequest.IssuanceRequestBuilder validRequest() {
        return IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(OBJECT_MAPPER.createObjectNode().put("key", "value"))
                .email("test@example.com");
    }

    @ParameterizedTest
    @ValueSource(strings = {"direct", "email,ui", "e;mail", "direct\r\nX-Forged-Header: 1", ""})
    void delivery_IsLeftToTheWorkflow(String delivery) {
        assertThat(validator.validate(validRequest().delivery(delivery).build())).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"authorization_code", "client_credentials", "authorization_code\r\nX: 1", ""})
    void grantType_IsLeftToTheWorkflow(String grantType) {
        assertThat(validator.validate(validRequest().grantType(grantType).build())).isEmpty();
    }
}
