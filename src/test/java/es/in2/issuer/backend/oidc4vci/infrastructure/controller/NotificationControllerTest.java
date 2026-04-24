package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.HandleNotificationWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NotificationControllerTest {

    private static final String PUBLIC_BASE_URL = "https://test.example/issuer";

    @Mock
    private HandleNotificationWorkflow handleNotificationWorkflow;

    @Mock
    private UrlResolver urlResolver;

    @InjectMocks
    private NotificationController notificationController;

    private static ServerWebExchange newExchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.post("/oid4vci/v1/notification"));
    }

    @Test
    void handleNotification_ok_shouldCleanBearerAndCallService_andComplete() {
        // given
        NotificationRequest request = mock(NotificationRequest.class);
        String authorization = "Bearer abc.def.ghi";
        ServerWebExchange exchange = newExchange();

        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(handleNotificationWorkflow.handleNotification(anyString(), eq(request), eq(authorization), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.empty());

        // when
        Mono<Void> result = notificationController.handleNotification(request, authorization, exchange);

        // then
        StepVerifier.create(result).verifyComplete();

        ArgumentCaptor<String> processIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(handleNotificationWorkflow).handleNotification(processIdCaptor.capture(), eq(request), eq(authorization), eq(PUBLIC_BASE_URL));

        String processId = processIdCaptor.getValue();
        assertNotNull(processId);
        assertFalse(processId.isBlank());

        UUID parsed = UUID.fromString(processId);
        assertNotNull(parsed);
    }

    @Test
    void handleNotification_whenNotificationServiceFails_shouldError() {
        // given
        NotificationRequest request = mock(NotificationRequest.class);
        String authorization = "Bearer token";
        RuntimeException error = new RuntimeException("service failed");
        ServerWebExchange exchange = newExchange();

        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(handleNotificationWorkflow.handleNotification(anyString(), eq(request), eq(authorization), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.error(error));

        // when
        Mono<Void> result = notificationController.handleNotification(request, authorization, exchange);

        // then
        StepVerifier.create(result)
                .expectErrorSatisfies(e -> assertFalse(e.getMessage().isBlank()))
                .verify();

        verify(handleNotificationWorkflow).handleNotification(anyString(), eq(request), eq(authorization), eq(PUBLIC_BASE_URL));
    }
}
