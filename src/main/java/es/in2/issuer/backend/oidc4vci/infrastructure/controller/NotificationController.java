package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.HandleNotificationWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oid4vci/v1/notification")
@RequiredArgsConstructor
public class NotificationController {

    private final HandleNotificationWorkflow handleNotificationWorkflow;
    private final UrlResolver urlResolver;

    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> handleNotification(@RequestBody @Valid NotificationRequest request,
                                         @RequestHeader("Authorization") String authorization,
                                         ServerWebExchange exchange) {
        String processId = UUID.randomUUID().toString();
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);
        return Mono.defer(() -> {
                    log.info("Process ID: {} - Handle notification start", processId);
                    return handleNotificationWorkflow.handleNotification(processId, request, authorization, publicIssuerBaseUrl);
                })
                .doOnSuccess(v ->
                        log.info("Process ID: {} - Handle notification ok", processId)
                )
                .doOnError(e ->
                        log.warn("Process ID: {} - Handle notification failed: {}", processId, e.getMessage(), e)
                );
    }
}
