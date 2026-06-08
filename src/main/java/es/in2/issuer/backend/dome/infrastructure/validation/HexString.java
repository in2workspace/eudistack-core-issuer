package es.in2.issuer.backend.dome.infrastructure.validation;

import jakarta.validation.Payload;

public @interface HexString {
    String message() default "Must be a valid hex string of exact length";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    int length();
}
