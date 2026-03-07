package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.issuance.domain.exception.*;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.signing.domain.exception.SigningResultParsingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.NoSuchElementException;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final ErrorResponseFactory errors;
    private final NonceService nonceService;

    @ExceptionHandler(RemoteSignatureException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public Mono<GlobalErrorMessage> handleRemoteSignatureException(
            RemoteSignatureException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.REMOTE_SIGNATURE.getCode(),
                "Remote signature error",
                HttpStatus.BAD_GATEWAY,
                "An error occurred during remote signature operation"
        );
    }

    @ExceptionHandler(CredentialTypeUnsupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleCredentialTypeUnsupported(
            CredentialTypeUnsupportedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_TYPE.getCode(),
                "Unsupported credential type",
                HttpStatus.BAD_REQUEST,
                "The given credential_configuration_id is not supported by this issuer"
        );
    }

    @ExceptionHandler(InvalidCredentialRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidCredentialRequest(
            InvalidCredentialRequestException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_CREDENTIAL_REQUEST.getCode(),
                "Invalid credential request",
                HttpStatus.BAD_REQUEST,
                "The credential request is malformed or contains invalid parameters"
        );
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoSuchElementException(
            NoSuchElementException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.NO_SUCH_ELEMENT.getCode(),
                "Resource not found",
                HttpStatus.NOT_FOUND,
                "The requested resource was not found"
        );
    }

    @ExceptionHandler(InvalidOrMissingProofException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidOrMissingProof(
            InvalidOrMissingProofException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_OR_MISSING_PROOF.getCode(),
                "Invalid or missing proof",
                HttpStatus.BAD_REQUEST,
                "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce."
        ).flatMap(gem -> nonceService.issueNonce()
                .map(nonce -> gem.withNonce(nonce.cNonce(), nonce.cNonceExpiresIn())));
    }

    @ExceptionHandler(InvalidTokenException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<GlobalErrorMessage> handleInvalidToken(
            InvalidTokenException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_TOKEN.getCode(),
                "Invalid token",
                HttpStatus.UNAUTHORIZED,
                "Credential Request contains the wrong Access Token or the Access Token is missing"
        );
    }

    @ExceptionHandler(ParseException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleParseException(
            ParseException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Parse error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal parsing error occurred."
        );
    }

    @ExceptionHandler(Base45Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleBase45Exception(
            Base45Exception ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Base45 decoding error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal Base45 decoding error occurred."
        );
    }

    @ExceptionHandler(SigningResultParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleSigningResultParsingException(
            SigningResultParsingException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Signing result parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal signing result parsing error occurred."
        );
    }

    @ExceptionHandler(ParseCredentialJsonException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleParseCredentialJsonException(
            ParseCredentialJsonException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Credential JSON parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal credential JSON parsing error occurred."
        );
    }

    @ExceptionHandler(ProofValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleProofValidationException(
            ProofValidationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PROOF_VALIDATION_ERROR.getCode(),
                "Proof validation error",
                HttpStatus.BAD_REQUEST,
                "The provided proof is invalid."
        );
    }

    @ExceptionHandler(NoCredentialFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoCredentialFoundException(
            NoCredentialFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_NOT_FOUND.getCode(),
                "Credential not found",
                HttpStatus.NOT_FOUND,
                "No credential found."
        );
    }

    @ExceptionHandler(PreAuthorizationCodeGetException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handlePreAuthorizationCodeGetException(
            PreAuthorizationCodeGetException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PRE_AUTHORIZATION_CODE_GET.getCode(),
                "Pre-authorization code retrieval error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Failed to retrieve pre-authorization code."
        );
    }

    @ExceptionHandler(CredentialOfferNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleCredentialOfferNotFoundException(
            CredentialOfferNotFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_OFFER_NOT_FOUND.getCode(),
                "Credential offer not found",
                HttpStatus.NOT_FOUND,
                "Credential offer not found."
        );
    }

    @ExceptionHandler(CredentialAlreadyIssuedException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleCredentialAlreadyIssuedException(
            CredentialAlreadyIssuedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_ALREADY_ISSUED.getCode(),
                "Credential already issued",
                HttpStatus.CONFLICT,
                "The credential has already been issued."
        );
    }

    @ExceptionHandler(OperationNotSupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleOperationNotSupportedException(
            OperationNotSupportedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.OPERATION_NOT_SUPPORTED.getCode(),
                "Operation not supported",
                HttpStatus.BAD_REQUEST,
                "The given operation is not supported"
        );
    }

    @ExceptionHandler(JWTVerificationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<GlobalErrorMessage> handleJWTVerificationException(
            JWTVerificationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.JWT_VERIFICATION.getCode(),
                "JWT verification failed",
                HttpStatus.UNAUTHORIZED,
                "JWT verification failed."
        );
    }

    @ExceptionHandler(FormatUnsupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleFormatUnsupportedException(
            FormatUnsupportedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_FORMAT.getCode(),
                "Format not supported",
                HttpStatus.BAD_REQUEST,
                "Format is not supported"
        );
    }

    @ExceptionHandler(InsufficientPermissionException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleInsufficientPermissionException(
            InsufficientPermissionException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INSUFFICIENT_PERMISSION.getCode(),
                "Insufficient permission",
                HttpStatus.FORBIDDEN,
                "The client who made the issuance request do not have the required permissions"
        );
    }

    @ExceptionHandler(UnauthorizedRoleException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<GlobalErrorMessage> handleUnauthorizedRoleException(
            UnauthorizedRoleException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNAUTHORIZED_ROLE.getCode(),
                "Unauthorized role",
                HttpStatus.UNAUTHORIZED,
                "The user role is not authorized to perform this action"
        );
    }

    @ExceptionHandler(EmailCommunicationException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public Mono<GlobalErrorMessage> handleEmailCommunicationException(
            EmailCommunicationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.EMAIL_COMMUNICATION.getCode(),
                "Email communication error",
                HttpStatus.SERVICE_UNAVAILABLE,
                "Email communication failed"
        );
    }

    @ExceptionHandler(MissingIdTokenHeaderException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleMissingIdTokenHeaderException(
            MissingIdTokenHeaderException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.MISSING_HEADER.getCode(),
                "Missing header",
                HttpStatus.BAD_REQUEST,
                "The X-ID-TOKEN header is missing, this header is needed to issue a Verifiable Certification"
        );
    }

    @ExceptionHandler(SadException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public Mono<GlobalErrorMessage> handleSadException(
            SadException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.SAD_ERROR.getCode(),
                "SAD error",
                HttpStatus.BAD_GATEWAY,
                "An upstream SAD error occurred"
        );
    }

    @ExceptionHandler(CredentialSerializationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleCredentialSerializationException(
            CredentialSerializationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_SERIALIZATION.getCode(),
                "Credential serialization error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An error occurred during credential serialization"
        );
    }

    @ExceptionHandler(JWTParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleJWTParsingException(
            JWTParsingException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_JWT.getCode(),
                "JWT parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "The provided JWT is invalid or can't be parsed."
        );
    }

    @ExceptionHandler(IssuanceInvalidStatusException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleIssuanceInvalidStatusException(
            IssuanceInvalidStatusException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.ISSUANCE_INVALID_STATUS.getCode(),
                "Invalid issuance status",
                HttpStatus.CONFLICT,
                "The issuance is not in a status that allows signing."
        );
    }

    @ExceptionHandler(IssuanceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleIssuanceNotFoundException(
            IssuanceNotFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.ISSUANCE_NOT_FOUND.getCode(),
                "Issuance not found",
                HttpStatus.NOT_FOUND,
                "The requested issuance was not found"
        );
    }

    @ExceptionHandler(TenantMismatchException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleTenantMismatchException(
            TenantMismatchException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.TENANT_MISMATCH.getCode(),
                "Tenant mismatch",
                HttpStatus.FORBIDDEN,
                "The token's organization does not match the requested tenant"
        );
    }

    @ExceptionHandler(PayloadValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handlePayloadValidationException(
            PayloadValidationException ex,
            ServerHttpRequest request
    ) {
        var violations = ex.getViolations().stream()
                .map(v -> new GlobalErrorMessage.FieldViolation(v.field(), v.message()))
                .toList();
        return errors.handleWithViolations(
                ex, request,
                GlobalErrorTypes.PAYLOAD_VALIDATION.getCode(),
                "Payload validation failed",
                HttpStatus.BAD_REQUEST,
                "The credential payload does not conform to the required schema",
                violations
        );
    }

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

    // SEC-13: Catch-all handler — never leaks internal details to the client
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @Order
    public Mono<GlobalErrorMessage> handleUnexpectedException(
            Exception ex,
            ServerHttpRequest request
    ) {
        return errors.handleSafe(
                ex, request,
                "INTERNAL_SERVER_ERROR",
                "Internal server error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred"
        );
    }

}
