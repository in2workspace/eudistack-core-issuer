package es.in2.issuer.backend.issuance.application.workflow;

import reactor.core.publisher.Mono;

public interface SendReminderWorkflow {
    Mono<Void> sendReminder(String processId, String issuanceId, String bearerToken);
}
