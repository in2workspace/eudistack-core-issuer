package es.in2.issuer.backend.backoffice.application.workflow;

import reactor.core.publisher.Mono;

public interface SendReminderWorkflow {
    Mono<Void> sendReminder(String processId, String procedureId, String bearerToken);
}
