package es.in2.issuer.backend.shared.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = UuidV7Validator.class)
public @interface ValidUuidV7 {
    String message() default "Must be a valid UUID version 7 (RFC 9562)";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
