package es.in2.issuer.backend.dome.infrastructure.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * Validator implementation for the @HexString annotation.
 * Ensures that a given String consists only of a valid hexadecimal characters
 * and matches the exact required length.
 */
public class HexStringValidator implements ConstraintValidator<HexString, String> {

    private int requiredLength;

    @Override
    public void initialize(HexString constraintAnnotation) {
        this.requiredLength = constraintAnnotation.length();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.length() != requiredLength) return false;
        return value.matches("^[0-9a-fA-F]{64}$");
    }
}
