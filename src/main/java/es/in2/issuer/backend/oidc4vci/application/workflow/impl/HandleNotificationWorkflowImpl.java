package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.application.workflow.HandleNotificationWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNotificationIdException;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNotificationRequestException;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
public class HandleNotificationWorkflowImpl implements HandleNotificationWorkflow {

    private final ProcedureService procedureService;
    private final RevocationWorkflow revocationWorkflow;
    private final CacheStore<String> notificationCacheStore;
    private final CacheStore<String> enrichmentCacheStore;
    private final AuditService auditService;

    public HandleNotificationWorkflowImpl(
            ProcedureService procedureService,
            RevocationWorkflow revocationWorkflow,
            @Qualifier("notificationCacheStore") CacheStore<String> notificationCacheStore,
            @Qualifier("enrichmentCacheStore") CacheStore<String> enrichmentCacheStore,
            AuditService auditService
    ) {
        this.procedureService = procedureService;
        this.revocationWorkflow = revocationWorkflow;
        this.notificationCacheStore = notificationCacheStore;
        this.enrichmentCacheStore = enrichmentCacheStore;
        this.auditService = auditService;
    }

    @Override
    @Observed(name = "notification.handle", contextualName = "notification-handle")
    public Mono<Void> handleNotification(String processId, NotificationRequest request, String bearerToken) {
        return Mono.justOrEmpty(request)
                .switchIfEmpty(Mono.error(new InvalidNotificationRequestException("Request body is required")))
                .doOnNext(this::validateRequest)
                .flatMap(req -> {
                    final String notificationId = req.notificationId();
                    final NotificationEvent event = req.event();
                    final String eventDescription = req.eventDescription();

                    auditService.auditSuccess("notification.received", null, "notification", notificationId,
                            Map.of("event", String.valueOf(event), "eventDescription", eventDescription != null ? eventDescription : ""));

                    return notificationCacheStore.get(notificationId)
                            .onErrorResume(e -> {
                                log.warn("AUDIT notification_rejected errorCode=invalid_notification_id notificationId={} event={}",
                                        notificationId, event
                                );
                                return Mono.error(new InvalidNotificationIdException(
                                        "The notification_id is not recognized: " + notificationId
                                ));
                            })
                            .flatMap(procedureId ->
                                    procedureService.getProcedureById(procedureId)
                                            .flatMap(proc -> handleEvent(processId, proc, event, bearerToken))
                            );
                })
                .onErrorResume(InvalidNotificationRequestException.class, e -> {
                    log.warn("AUDIT notification_rejected errorCode=invalid_notification_request errorDescription={}",
                            e.getMessage()
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

    private Mono<Void> handleEvent(String processId, CredentialProcedure procedure,
                                   NotificationEvent event, String bearerToken) {

        String procedureId = procedure.getProcedureId().toString();
        CredentialStatusEnum currentStatus = procedure.getCredentialStatus();

        log.info("AUDIT notification_processing procedureId={} event={} currentStatus={}",
                procedureId, event, currentStatus);

        // Notifications only apply while procedure is in DRAFT
        if (currentStatus != CredentialStatusEnum.DRAFT) {
            log.info("AUDIT notification_ignored procedureId={} event={} reason=not_in_draft currentStatus={}",
                    procedureId, event, currentStatus);
            return Mono.empty();
        }

        return switch (event) {
            case CREDENTIAL_ACCEPTED -> handleAccepted(processId, procedure);
            case CREDENTIAL_FAILURE -> handleFailure(processId, procedure);
            case CREDENTIAL_DELETED -> handleDeleted(processId, procedure, bearerToken);
        };
    }

    /**
     * credential_accepted: persist enriched data from cache -> DRAFT -> ISSUED
     */
    private Mono<Void> handleAccepted(String processId, CredentialProcedure procedure) {
        String procedureId = procedure.getProcedureId().toString();
        log.info("[{}] credential_accepted: persisting enriched data and transitioning to ISSUED for procedureId={}",
                processId, procedureId);

        return enrichmentCacheStore.get(procedureId)
                .flatMap(enrichedDataSet ->
                        procedureService.updateCredentialDataSetByProcedureId(
                                procedureId, enrichedDataSet, procedure.getCredentialFormat())
                )
                .doOnSuccess(v -> log.info("[{}] credential_accepted: procedureId={} transitioned to ISSUED",
                        processId, procedureId))
                .onErrorResume(e -> {
                    log.warn("[{}] credential_accepted: failed to persist enriched data for procedureId={}: {}",
                            processId, procedureId, e.getMessage());
                    return Mono.empty();
                });
    }

    /**
     * credential_failure: log only, stay in DRAFT. Wallet may retry.
     */
    private Mono<Void> handleFailure(String processId, CredentialProcedure procedure) {
        log.info("[{}] credential_failure: procedureId={} stays in DRAFT. Wallet may retry or request new offer.",
                processId, procedure.getProcedureId());
        return Mono.empty();
    }

    /**
     * credential_deleted: DRAFT -> WITHDRAWN + revoke status list entry
     */
    private Mono<Void> handleDeleted(String processId, CredentialProcedure procedure, String bearerToken) {
        String procedureId = procedure.getProcedureId().toString();
        log.info("[{}] credential_deleted: withdrawing procedureId={}", processId, procedureId);

        return procedureService.withdrawCredentialProcedure(procedureId)
                .then(revokeCredentialFromDecoded(processId, procedure, bearerToken))
                .doOnSuccess(v -> log.info("[{}] credential_deleted: procedureId={} withdrawn and status list entry revoked",
                        processId, procedureId))
                .onErrorResume(e -> {
                    log.warn("[{}] credential_deleted: error processing procedureId={}: {}",
                            processId, procedureId, e.getMessage());
                    return Mono.empty();
                });
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
