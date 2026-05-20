package es.in2.issuer.backend.shared.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

public @interface HexString {
    String message() default "Must be a valid hex string of exact length";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    int length();
}
