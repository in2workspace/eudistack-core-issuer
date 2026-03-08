package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.signing.domain.exception.SigningResultParsingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class SharedExceptionHandlerTest {

    private ErrorResponseFactory errors;
    private SharedExceptionHandler handler;
    private ServerHttpRequest request;

    @BeforeEach
    void setUp() {
        errors = mock(ErrorResponseFactory.class);
        handler = new SharedExceptionHandler(errors);
        request = MockServerHttpRequest.get("/any").build();
    }

    private void assertGem(GlobalErrorMessage gem,
                           String expectedType,
                           String expectedTitle,
                           HttpStatus expectedStatus,
                           String expectedDetail) {
        assertEquals(expectedType, gem.type());
        assertEquals(expectedTitle, gem.title());
        assertEquals(expectedStatus.value(), gem.status());
        assertEquals(expectedDetail, gem.detail());
        assertDoesNotThrow(() -> UUID.fromString(gem.instance()));
    }

    // -------------------- handleCredentialTypeUnsupported --------------------

    @Test
    void handleCredentialTypeUnsupported_usesExceptionMessage_whenPresent() {
        var ex = new CredentialTypeUnsupportedException("custom msg");
        var type = GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_TYPE.getCode();
        var title = "Unsupported credential type";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The given credential_configuration_id is not supported by this issuer";
        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialTypeUnsupported(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "custom msg"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleCredentialTypeUnsupported_usesFallback_whenMessageNullOrBlank() {
        var type = GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_TYPE.getCode();
        var title = "Unsupported credential type";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The given credential_configuration_id is not supported by this issuer";

        var exNull = new CredentialTypeUnsupportedException((String) null);
        var exBlank = new CredentialTypeUnsupportedException("   ");
        var expectedNull = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull, request, type, title, st, fallback))
                .thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback))
                .thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleCredentialTypeUnsupported(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();
        StepVerifier.create(handler.handleCredentialTypeUnsupported(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull, request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // -------------------- handleNoSuchElementException --------------------

    @Test
    void handleNoSuchElementException_usesExceptionMessage_whenPresent() {
        var ex = new NoSuchElementException("not here");
        var type = GlobalErrorTypes.NO_SUCH_ELEMENT.getCode();
        var title = "Resource not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "The requested resource was not found";
        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleNoSuchElementException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "not here"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleNoSuchElementException_usesFallback_whenMessageNullOrBlank() {
        var type = GlobalErrorTypes.NO_SUCH_ELEMENT.getCode();
        var title = "Resource not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "The requested resource was not found";

        var exBlank = new NoSuchElementException("  ");
        var expected = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exBlank, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleNoSuchElementException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // -------------------- handleInvalidToken --------------------

    @Test
    void handleInvalidToken_usesExceptionMessage_whenPresent() {
        var ex = new InvalidTokenException("Message");
        var type = GlobalErrorTypes.INVALID_TOKEN.getCode();
        var title = "Invalid token";
        var st = HttpStatus.UNAUTHORIZED;
        var fallback = "Credential Request contains the wrong Access Token or the Access Token is missing";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidToken(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "Message"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleInvalidToken_usesFallback_whenMessageNullOrBlank() {
        var type = GlobalErrorTypes.INVALID_TOKEN.getCode();
        var title = "Invalid token";
        var st = HttpStatus.UNAUTHORIZED;
        var fallback = "Credential Request contains the wrong Access Token or the Access Token is missing";

        var exNull = new InvalidTokenException((String) null);
        var exBlank = new InvalidTokenException("   ");

        var expectedNull = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull, request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleInvalidToken(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();
        StepVerifier.create(handler.handleInvalidToken(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull, request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // -------------------- handleParseException --------------------

    @Test
    void handleParseException_usesExceptionMessage_whenPresent() {
        var ex = new ParseException("bad date", 0);
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Parse error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal parsing error occurred.";
        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleParseException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "bad date"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleParseException_usesFallback_whenMessageNullOrBlank() {
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Parse error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal parsing error occurred.";

        var exNull = new ParseException(null, 0);
        var exBlank = new ParseException("   ", 0);

        var expectedNull = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull, request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleParseException(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();
        StepVerifier.create(handler.handleParseException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull, request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // -------------------- handleBase45Exception --------------------

    @Test
    void handleBase45Exception() {
        var ex = new Base45Exception("decode failed");
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Base45 decoding error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal Base45 decoding error occurred.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "decode failed", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleBase45Exception(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "decode failed"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleSignedDataParsingException --------------------

    @Test
    void handleSigningResultParsingException() {
        var ex = new SigningResultParsingException("bad signature payload");
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Signing result parsing error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal signing result parsing error occurred.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "bad signature payload", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleSigningResultParsingException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "bad signature payload"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleParseCredentialJsonException --------------------

    @Test
    void handleParseCredentialJsonException() {
        var ex = new ParseCredentialJsonException("bad json");
        var type = GlobalErrorTypes.PARSE_ERROR.getCode();
        var title = "Credential JSON parsing error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An internal credential JSON parsing error occurred.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "bad json", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleParseCredentialJsonException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "bad json"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleNoCredentialFoundException --------------------

    @Test
    void handleNoCredentialFoundException() {
        var ex = new NoCredentialFoundException("nothing here");
        var type = GlobalErrorTypes.CREDENTIAL_NOT_FOUND.getCode();
        var title = "Credential not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "No credential found.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "nothing here", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleNoCredentialFoundException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "nothing here"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handlePreAuthorizationCodeGetException --------------------

    @Test
    void handlePreAuthorizationCodeGetException() {
        var ex = new PreAuthorizationCodeGetException("service down");
        var type = GlobalErrorTypes.PRE_AUTHORIZATION_CODE_GET.getCode();
        var title = "Pre-authorization code retrieval error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "Failed to retrieve pre-authorization code.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "service down", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handlePreAuthorizationCodeGetException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "service down"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleCredentialOfferNotFoundException --------------------

    @Test
    void handleCredentialOfferNotFoundException() {
        var ex = new CredentialOfferNotFoundException("offer not found");
        var type = GlobalErrorTypes.CREDENTIAL_OFFER_NOT_FOUND.getCode();
        var title = "Credential offer not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "Credential offer not found.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "offer not found", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialOfferNotFoundException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "offer not found"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleCredentialAlreadyIssuedException --------------------

    @Test
    void handleCredentialAlreadyIssuedException() {
        var ex = new CredentialAlreadyIssuedException("already issued");
        var type = GlobalErrorTypes.CREDENTIAL_ALREADY_ISSUED.getCode();
        var title = "Credential already issued";
        var st = HttpStatus.CONFLICT;
        var fallback = "The credential has already been issued.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "already issued", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialAlreadyIssuedException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "already issued"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleOperationNotSupportedException --------------------

    @Test
    void handleOperationNotSupportedException() {
        var ex = new OperationNotSupportedException("not allowed");
        var type = GlobalErrorTypes.OPERATION_NOT_SUPPORTED.getCode();
        var title = "Operation not supported";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The given operation is not supported";
        var expected = new GlobalErrorMessage(type, title, st.value(), "not allowed", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleOperationNotSupportedException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "not allowed"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleJWTVerificationException --------------------

    @Test
    void handleJWTVerificationException() {
        var ex = new JWTVerificationException("jwt invalid");
        var type = GlobalErrorTypes.JWT_VERIFICATION.getCode();
        var title = "JWT verification failed";
        var st = HttpStatus.UNAUTHORIZED;
        var fallback = "JWT verification failed.";
        var expected = new GlobalErrorMessage(type, title, st.value(), "jwt invalid", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleJWTVerificationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "jwt invalid"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleFormatUnsupportedException --------------------

    @Test
    void handleFormatUnsupportedException() {
        var ex = new FormatUnsupportedException("format xyz not supported");
        var type = GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_FORMAT.getCode();
        var title = "Format not supported";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "Format is not supported";
        var expected = new GlobalErrorMessage(type, title, st.value(), "format xyz not supported", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleFormatUnsupportedException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "format xyz not supported"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleInsufficientPermissionException --------------------

    @Test
    void handleInsufficientPermissionException() {
        var ex = new InsufficientPermissionException("no perms");
        var type = GlobalErrorTypes.INSUFFICIENT_PERMISSION.getCode();
        var title = "Insufficient permission";
        var st = HttpStatus.FORBIDDEN;
        var fallback = "The client who made the issuance request do not have the required permissions";
        var expected = new GlobalErrorMessage(type, title, st.value(), "no perms", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInsufficientPermissionException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "no perms"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleUnauthorizedRoleException --------------------

    @Test
    void handleUnauthorizedRoleException() {
        var ex = new UnauthorizedRoleException("role not allowed");
        var type = GlobalErrorTypes.UNAUTHORIZED_ROLE.getCode();
        var title = "Unauthorized role";
        var st = HttpStatus.UNAUTHORIZED;
        var fallback = "The user role is not authorized to perform this action";
        var expected = new GlobalErrorMessage(type, title, st.value(), "role not allowed", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleUnauthorizedRoleException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "role not allowed"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleEmailCommunicationException --------------------

    @Test
    void handleEmailCommunicationException() {
        var ex = new EmailCommunicationException("smtp down");
        var type = GlobalErrorTypes.EMAIL_COMMUNICATION.getCode();
        var title = "Email communication error";
        var st = HttpStatus.SERVICE_UNAVAILABLE;
        var fallback = "Email communication failed";
        var expected = new GlobalErrorMessage(type, title, st.value(), "smtp down", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleEmailCommunicationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "smtp down"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleMissingIdTokenHeaderException --------------------

    @Test
    void handleMissingIdTokenHeaderException() {
        var ex = new MissingIdTokenHeaderException("header missing");
        var type = GlobalErrorTypes.MISSING_HEADER.getCode();
        var title = "Missing header";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The X-ID-TOKEN header is missing, this header is needed to issue a Verifiable Certification";
        var expected = new GlobalErrorMessage(type, title, st.value(), "header missing", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleMissingIdTokenHeaderException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "header missing"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleSadException--------------------

    @Test
    void handleSadException() {
        var ex = new SadException("upstream SAD failed");
        var type = GlobalErrorTypes.SAD_ERROR.getCode();
        var title = "SAD error";
        var st = HttpStatus.BAD_GATEWAY;
        var fallback = "An upstream SAD error occurred";
        var expected = new GlobalErrorMessage(type, title, st.value(), "upstream SAD failed", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleSadException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "upstream SAD failed"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleCredentialSerializationException --------------------

    @Test

    void handleCredentialSerializationException() {
        var ex = new CredentialSerializationException("Credential serialization err");
        var type = GlobalErrorTypes.CREDENTIAL_SERIALIZATION.getCode();
        var title = "Credential serialization error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "An error occurred during credential serialization";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "Credential serialization err",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleCredentialSerializationException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "Credential serialization err"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleJWTParsingExceptionTest --------------------

    @Test
    void handleJWTParsingExceptionTest() {
        var ex = new JWTParsingException("jwt parsing exception");
        var type = GlobalErrorTypes.INVALID_JWT.getCode();
        var title = "JWT parsing error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var fallback = "The provided JWT is invalid or can't be parsed.";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "jwt parsing exception",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleJWTParsingException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "jwt parsing exception"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleIssuanceInvalidStatusException --------------------

    @Test
    void handleIssuanceInvalidStatusException() {
        var ex = new IssuanceInvalidStatusException("procedure status exception");
        var type = GlobalErrorTypes.ISSUANCE_INVALID_STATUS.getCode();
        var title = "Invalid issuance status";
        var st = HttpStatus.CONFLICT;
        var fallback = "The issuance is not in a status that allows signing.";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "invalid procedure status",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleIssuanceInvalidStatusException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "invalid procedure status"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

// -------------------- handleIssuanceNotFoundException --------------------

    @Test
    void handleIssuanceNotFoundException() {
        var ex = new IssuanceNotFoundException("procedure not found");
        var type = GlobalErrorTypes.ISSUANCE_NOT_FOUND.getCode();
        var title = "Issuance not found";
        var st = HttpStatus.NOT_FOUND;
        var fallback = "The requested issuance was not found";

        var expected = new GlobalErrorMessage(
                type,
                title,
                st.value(),
                "procedure not found",
                UUID.randomUUID().toString()
        );

        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleIssuanceNotFoundException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "procedure not found"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleInvalidCredentialRequest --------------------

    @Test
    void handleInvalidCredentialRequest() {
        var ex = new InvalidCredentialRequestException("missing required field");
        var type = GlobalErrorTypes.INVALID_CREDENTIAL_REQUEST.getCode();
        var title = "Invalid credential request";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The credential request is malformed or contains invalid parameters";
        var expected = new GlobalErrorMessage(type, title, st.value(), "missing required field", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidCredentialRequest(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "missing required field"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleRemoteSignatureException --------------------

    @Test
    void handleRemoteSignatureException() {
        var ex = new RemoteSignatureException("signature service error");
        var type = GlobalErrorTypes.REMOTE_SIGNATURE.getCode();
        var title = "Remote signature error";
        var st = HttpStatus.BAD_GATEWAY;
        var fallback = "An error occurred during remote signature operation";
        var expected = new GlobalErrorMessage(type, title, st.value(), "signature service error", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleRemoteSignatureException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "signature service error"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handleTenantMismatchException --------------------

    @Test
    void handleTenantMismatchException() {
        var ex = new TenantMismatchException("tenant does not match");
        var type = GlobalErrorTypes.TENANT_MISMATCH.getCode();
        var title = "Tenant mismatch";
        var st = HttpStatus.FORBIDDEN;
        var fallback = "The token's organization does not match the requested tenant";
        var expected = new GlobalErrorMessage(type, title, st.value(), "tenant does not match", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, fallback)).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleTenantMismatchException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "tenant does not match"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    // -------------------- handlePayloadValidationException --------------------

    @Test
    void handlePayloadValidationException() {
        var violations = List.of(
                new PayloadValidationException.Violation("field1", "must not be null"),
                new PayloadValidationException.Violation("field2", "must be positive")
        );
        var ex = new PayloadValidationException("validation failed", violations);
        var type = GlobalErrorTypes.PAYLOAD_VALIDATION.getCode();
        var title = "Payload validation failed";
        var st = HttpStatus.BAD_REQUEST;
        var fallback = "The credential payload does not conform to the required schema";

        var expectedViolations = List.of(
                new GlobalErrorMessage.FieldViolation("field1", "must not be null"),
                new GlobalErrorMessage.FieldViolation("field2", "must be positive")
        );
        var expected = new GlobalErrorMessage(type, title, st.value(), "validation failed", UUID.randomUUID().toString(), expectedViolations);

        when(errors.handleWithViolations(ex, request, type, title, st, fallback, expectedViolations))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handlePayloadValidationException(ex, request))
                .assertNext(gem -> {
                    assertGem(gem, type, title, st, "validation failed");
                    assertEquals(2, gem.violations().size());
                    assertEquals("field1", gem.violations().get(0).field());
                    assertEquals("must not be null", gem.violations().get(0).message());
                })
                .verifyComplete();

        verify(errors).handleWithViolations(ex, request, type, title, st, fallback, expectedViolations);
    }

    // -------------------- handleUnexpectedException --------------------

    @Test
    void handleUnexpectedException_neverLeaksInternalDetails() {
        var ex = new RuntimeException("sensitive internal details");
        var type = "INTERNAL_SERVER_ERROR";
        var title = "Internal server error";
        var st = HttpStatus.INTERNAL_SERVER_ERROR;
        var detail = "An unexpected error occurred";
        var expected = new GlobalErrorMessage(type, title, st.value(), detail, UUID.randomUUID().toString());

        when(errors.handleSafe(ex, request, type, title, st, detail))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleUnexpectedException(ex, request))
                .assertNext(gem -> {
                    assertGem(gem, type, title, st, detail);
                    assertFalse(gem.detail().contains("sensitive"));
                })
                .verifyComplete();

        verify(errors).handleSafe(ex, request, type, title, st, detail);
    }

}
