package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;

public final class SigningRequestValidator {

    private SigningRequestValidator() {}

    /**
     * AD-1/EUD-225: {@link es.in2.issuer.backend.signing.domain.model.dto.SigningContext#token()}
     * is deliberately NOT validated. It is vestigial downstream -- no signing provider reads it,
     * and the QTSP acquires its own credentials -- so requiring it only made signing fail for
     * callers that legitimately have no access token to hand over.
     */
    public static void validate(SigningRequest request) {
        validateNotNull(request);
        validateType(request);
        validateData(request);
        validateContext(request);
    }

    private static void validateNotNull(SigningRequest request) {
        if (request == null) {
            throw new SigningException("SigningRequest must not be null");
        }
    }

    private static void validateType(SigningRequest request) {
        if (request.type() == null) {
            throw new SigningException("SigningRequest.type must not be null");
        }
    }

    private static void validateData(SigningRequest request) {
        if (request.data() == null || request.data().isBlank()) {
            throw new SigningException("SigningRequest.data must not be null/blank");
        }
    }

    private static void validateContext(SigningRequest request) {
        if (request.context() == null) {
            throw new SigningException("SigningRequest.context must not be null");
        }
    }
}
