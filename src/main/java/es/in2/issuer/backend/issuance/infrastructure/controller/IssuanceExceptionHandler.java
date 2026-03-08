package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.exception.*;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
@Order(2)
public class IssuanceExceptionHandler {

    private final ErrorResponseFactory errors;

    @ExceptionHandler(AuthenticSourcesUserParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleAuthenticSourcesUserParsingException(
            AuthenticSourcesUserParsingException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Authentic sources user parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal authentic-sources user parsing error occurred."
        );
    }

    @ExceptionHandler(TemplateReadException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleTemplateReadException(
            TemplateReadException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.TEMPLATE_READ_ERROR.getCode(),
                "Template read error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal template read error occurred."
        );
    }

    @ExceptionHandler(OrganizationIdentifierMismatchException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleOrganizationIdentifierMismatchException(
            OrganizationIdentifierMismatchException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.ORGANIZATION_ID_MISMATCH.getCode(),
                "Forbidden",
                HttpStatus.FORBIDDEN,
                "Organization identifier mismatch"
        );
    }

    @ExceptionHandler(NoSuchEntityException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoSuchEntityException(
            NoSuchEntityException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.NO_SUCH_ENTITY.getCode(),
                "Not Found",
                HttpStatus.NOT_FOUND,
                "Requested entity was not found"
        );
    }

    @ExceptionHandler(MissingRequiredDataException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleMissingRequiredDataException(
            MissingRequiredDataException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.MISSING_REQUIRED_DATA.getCode(),
                "Bad Request",
                HttpStatus.BAD_REQUEST,
                "Missing required data"
        );
    }

    @ExceptionHandler(InvalidStatusException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleInvalidStatusException(
            InvalidStatusException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_STATUS.getCode(),
                "Invalid status",
                HttpStatus.CONFLICT,
                "The entity is not in a valid status for this operation"
        );
    }
}