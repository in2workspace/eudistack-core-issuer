package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.application.workflow.HandleNotificationWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNotificationIdException;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNotificationRequestException;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class HandleNotificationWorkflowImpl implements HandleNotificationWorkflow {

    private final CredentialProcedureService credentialProcedureService;
    private final RevocationWorkflow revocationWorkflow;

    @Override
    public Mono<Void> handleNotification(String processId, NotificationRequest request, String bearerToken) {
        return Mono.justOrEmpty(request)
                .switchIfEmpty(Mono.error(new InvalidNotificationRequestException("Request body is required")))
                .doOnNext(this::validateRequest)
                .flatMap(req -> {
                    final String notificationId = req.notificationId();
                    final NotificationEvent event = req.event();
                    final String eventDescription = req.eventDescription();

                    log.info("AUDIT notification_received notificationId={} event={} eventDescription={}",
                            notificationId, event, eventDescription
                    );

                    return credentialProcedureService.getCredentialProcedureByNotificationId(notificationId)
                            .switchIfEmpty(Mono.defer(() -> {
                                log.warn("AUDIT notification_rejected errorCode=invalid_notification_id errorDescription={} notificationId={} event={}",
                                        "The notification_id is not recognized", notificationId, event
                                );
                                return Mono.error(new InvalidNotificationIdException(
                                        "The notification_id is not recognized: " + notificationId
                                ));
                            }))
                            .flatMap(proc -> applyIdempotentUpdate(processId, proc, event, eventDescription, bearerToken));
                })
                .onErrorResume(InvalidNotificationRequestException.class, e -> {
                    String nid = request != null ? request.notificationId() : null;
                    NotificationEvent ev = request != null ? request.event() : null;

                    log.warn("AUDIT notification_rejected errorCode=invalid_notification_request errorDescription={} notificationId={} event={}",
                            e.getMessage(), nid, ev
                    );
                    return Mono.error(e);
                })
                .then();
    }

    private void validateRequest(NotificationRequest request) {
        if (request.notificationId() == null || request.notificationId().isBlank()) {
            throw new InvalidNotificationRequestException("notification_id is required");
        }
    }

    private Mono<Void> applyIdempotentUpdate(String processId,
                                             CredentialProcedure procedure,
                                             NotificationEvent event,
                                             String eventDescription,
                                             String bearerToken) {

        final CredentialStatusEnum before = procedure.getCredentialStatus();
        final CredentialStatusEnum mappedAfter = mapEventToCredentialStatus(event);
        final boolean idempotent = (before == mappedAfter);

        log.info("AUDIT notification_processing credentialProcedureId={} notificationId={} event={} idempotent={} statusBefore={} statusAfter={}",
                procedure.getProcedureId(),
                procedure.getNotificationId(),
                event,
                idempotent,
                before,
                mappedAfter
        );

        if (idempotent) {
            log.info("AUDIT notification_idempotent credentialProcedureId={} notificationId={} event={} status={}",
                    procedure.getProcedureId(),
                    procedure.getNotificationId(),
                    event,
                    before
            );
            return Mono.empty();
        }

        if (event != NotificationEvent.CREDENTIAL_DELETED) {
            log.info("AUDIT notification_no_external_action processId={} credentialProcedureId={} notificationId={} event={} eventDescription={}",
                    processId, procedure.getProcedureId(), procedure.getNotificationId(), event, eventDescription
            );
            return Mono.empty();
        }

        return revokeCredentialFromDecoded(processId, procedure, bearerToken);
    }

    private CredentialStatusEnum mapEventToCredentialStatus(NotificationEvent event) {
        return switch (event) {
            case CREDENTIAL_ACCEPTED, CREDENTIAL_FAILURE -> CredentialStatusEnum.VALID;
            case CREDENTIAL_DELETED -> CredentialStatusEnum.REVOKED;
        };
    }

    private Mono<Void> revokeCredentialFromDecoded(String processId, CredentialProcedure procedure, String bearerToken) {
        String procedureId = procedure.getProcedureId().toString();
        return revocationWorkflow.revokeSystem(processId, bearerToken, procedureId)
                .doFirst(() -> log.info("processId={} action=revokeCredential status=started procedureId={}",
                        processId, procedureId))
                .doOnSuccess(v -> log.info("processId={} action=revokeCredential status=completed procedureId={}",
                        processId, procedureId))
                .doOnError(e -> log.warn("processId={} action=revokeCredential status=failed procedureId={} error={}",
                        processId, procedureId, e.getMessage(), e));
    }
}
