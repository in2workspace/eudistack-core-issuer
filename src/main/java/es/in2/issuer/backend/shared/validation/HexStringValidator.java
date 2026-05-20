package es.in2.issuer.backend.shared.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class HexStringValidator implements ConstraintValidator<HexString, String> {

    private int requiredLength;

    @Override
    public void initialize(HexString constraintAnnotation) {
        this.requiredLength = constraintAnnotation.length();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.length() != requiredLength) return false;
        return value.matches("^[0-9a-fA-F]+$]");
    }
}
