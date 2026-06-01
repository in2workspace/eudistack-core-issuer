package es.in2.issuer.backend.dome.infrastructure.controller;

import es.in2.issuer.backend.dome.domain.exception.ConflictingMigrationStateException;
import es.in2.issuer.backend.dome.domain.exception.HashMismatchException;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("KeyMigrationExceptionHandler — exception-to-HTTP mapping")
class KeyMigrationExceptionHandlerTest {

    @Mock
    private ErrorResponseFactory errors;

    @InjectMocks
    private KeyMigrationExceptionHandler handler;

    private static final GlobalErrorMessage DUMMY_RESPONSE =
            new GlobalErrorMessage("TYPE", "Title", 409, "detail", "/uri");

    @Test
    @DisplayName("handleConflictingMigrationState — returns Mono with response from factory")
    void handleConflictingMigrationState_returnsMonoFromFactory() {
        var request = MockServerHttpRequest.get("/migrate").build();
        var ex = new ConflictingMigrationStateException("already migrated");

        when(errors.handleWith(eq(ex), any(), eq("CONFLICTING_MIGRATION_STATE"), any(),
                eq(HttpStatus.CONFLICT), any()))
                .thenReturn(Mono.just(DUMMY_RESPONSE));

        StepVerifier.create(handler.handleConflictingMigrationState(ex, request))
                .expectNextMatches(msg -> "TYPE".equals(msg.type()))
                .verifyComplete();

        verify(errors).handleWith(eq(ex), any(), eq("CONFLICTING_MIGRATION_STATE"), any(),
                eq(HttpStatus.CONFLICT), any());
    }

    @Test
    @DisplayName("handleHashMismatch — returns Mono with response from factory")
    void handleHashMismatch_returnsMonoFromFactory() {
        var request = MockServerHttpRequest.get("/poc").build();
        var ex = new HashMismatchException("signature did not verify");

        when(errors.handleWith(eq(ex), any(), eq("KEY_MATERIAL_VALIDATION_FAILURE"), any(),
                eq(HttpStatus.INTERNAL_SERVER_ERROR), any()))
                .thenReturn(Mono.just(DUMMY_RESPONSE));

        StepVerifier.create(handler.handleHashMismatch(ex, request))
                .expectNextMatches(msg -> "TYPE".equals(msg.type()))
                .verifyComplete();

        verify(errors).handleWith(eq(ex), any(), eq("KEY_MATERIAL_VALIDATION_FAILURE"), any(),
                eq(HttpStatus.INTERNAL_SERVER_ERROR), any());
    }
}

