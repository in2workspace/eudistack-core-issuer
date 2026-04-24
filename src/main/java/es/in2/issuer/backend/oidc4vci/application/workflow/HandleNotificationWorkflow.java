package es.in2.issuer.backend.oidc4vci.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import reactor.core.publisher.Mono;

public interface HandleNotificationWorkflow {
    Mono<Void> handleNotification(String processId, NotificationRequest request, String bearerToken,
                                  String publicIssuerBaseUrl);
}
