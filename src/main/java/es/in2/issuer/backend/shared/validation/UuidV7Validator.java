package es.in2.issuer.backend.shared.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.UUID;

/**
 * Validator implementation for the @ValidUuid7 annotation.
 * Ensures that a given UUID object specifically corresponds to version 7.
 */
public class UuidV7Validator implements ConstraintValidator<ValidUuidV7, UUID> {
    @Override
    public boolean isValid(UUID value, ConstraintValidatorContext context) {
        if (value == null) return false;

        try { return value.version() == 7; }
        catch (Exception e) { return false; }
    }
}
