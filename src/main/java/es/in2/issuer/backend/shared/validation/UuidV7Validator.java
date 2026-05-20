package es.in2.issuer.backend.shared.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.UUID;

public class UuidV7Validator implements ConstraintValidator<ValidUuidV7, UUID> {
    @Override
    public boolean isValid(UUID value, ConstraintValidatorContext context) {
        if (value == null) return false;

        try { return value.version() == 7; }
        catch (Exception e) { return false; }
    }
}
