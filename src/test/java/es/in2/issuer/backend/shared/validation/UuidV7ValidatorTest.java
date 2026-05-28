package es.in2.issuer.backend.shared.validation;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class UuidV7ValidatorTest {

   private UuidV7Validator validator;

   @Mock
   private ConstraintValidatorContext context;

   @BeforeEach
   void setUp() {
       MockitoAnnotations.openMocks(this);
       validator = new UuidV7Validator();
   }

    @Test
    @DisplayName("Must accept a valid UUIDv7 (RFC 9562)")
    void acceptValidUuidV7() {
        UUID validV7 = UUID.fromString("018f3a3c-b3a1-7b34-8c11-9a1f2b3c4d5e");
        assertTrue(validator.isValid(validV7, context), "The UUIDv7 should be valid");
    }

    @Test
    @DisplayName("Must reject a traditional UUIDv4")
    void rejectUuidV4() {
        UUID invalidV4 = UUID.fromString("f47ac10b-58cc-4372-a567-0e02b2c3d479");
        assertFalse(validator.isValid(invalidV4, context), "UUIDv4 is not allowed");
    }

    @Test
    @DisplayName("Must reject UUIDs from others versions (e.g., v5)")
    void rejectUuidsV5() {
        UUID invalidV5 = UUID.fromString("018f3a3c-b3a1-5b34-8c11-9a1f2b3c4d5e");
        assertFalse(validator.isValid(invalidV5, context), "UUIDv4 is not allowed");
    }

    @Test
    @DisplayName("Must safely handle and reject null values")
    void rejectNullValues() {
        assertFalse(validator.isValid(null, context), "Null values must return false without throwing exceptions");
    }
}