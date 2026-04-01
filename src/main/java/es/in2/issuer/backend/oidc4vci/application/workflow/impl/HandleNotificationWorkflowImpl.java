package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.application.workflow.HandleNotificationWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNotificationIdException;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNotificationRequestException;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationEvent;
import es.in2.issuer.backend.shared.domain.model.dto.NotificationRequest;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
public class HandleNotificationWorkflowImpl implements HandleNotificationWorkflow {

    private final IssuanceService issuanceService;
    private final RevocationWorkflow revocationWorkflow;
    private final TransientStore<String> notificationCacheStore;
    private final TransientStore<String> enrichmentCacheStore;
    private final AuditService auditService;
    private final EmailService emailService;

    public HandleNotificationWorkflowImpl(
            IssuanceService issuanceService,
            RevocationWorkflow revocationWorkflow,
            @Qualifier("notificationCacheStore") TransientStore<String> notificationCacheStore,
            @Qualifier("enrichmentCacheStore") TransientStore<String> enrichmentCacheStore,
            AuditService auditService,
            EmailService emailService
    ) {
        this.issuanceService = issuanceService;
        this.revocationWorkflow = revocationWorkflow;
        this.notificationCacheStore = notificationCacheStore;
        this.enrichmentCacheStore = enrichmentCacheStore;
        this.auditService = auditService;
        this.emailService = emailService;
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
                            .flatMap(issuanceId ->
                                    issuanceService.getIssuanceById(issuanceId)
                                            .flatMap(proc -> handleEvent(processId, proc, event, eventDescription, bearerToken))
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

    private Mono<Void> handleEvent(String processId, Issuance issuance,
                                   NotificationEvent event, String eventDescription, String bearerToken) {

        String issuanceId = issuance.getIssuanceId().toString();
        CredentialStatusEnum currentStatus = issuance.getCredentialStatus();

        log.info("AUDIT notification_processing issuanceId={} event={} currentStatus={}",
                issuanceId, event, currentStatus);

        // Notifications only apply while procedure is in DRAFT
        if (currentStatus != CredentialStatusEnum.DRAFT) {
            log.info("AUDIT notification_ignored issuanceId={} event={} reason=not_in_draft currentStatus={}",
                    issuanceId, event, currentStatus);
            return Mono.empty();
        }

        return switch (event) {
            case CREDENTIAL_ACCEPTED -> handleAccepted(processId, issuance);
            case CREDENTIAL_FAILURE -> handleFailure(processId, issuance, eventDescription);
            case CREDENTIAL_DELETED -> handleDeleted(processId, issuance, bearerToken);
        };
    }

    /**
     * credential_accepted: persist enriched data from cache -> DRAFT -> ISSUED (-> VALID if ready)
     */
    private Mono<Void> handleAccepted(String processId, Issuance issuance) {
        String issuanceId = issuance.getIssuanceId().toString();
        log.info("[{}] credential_accepted: persisting enriched data and transitioning to ISSUED for issuanceId={}",
                processId, issuanceId);

        return enrichmentCacheStore.get(issuanceId)
                .flatMap(enrichedDataSet ->
                        issuanceService.updateCredentialDataSetByIssuanceId(
                                issuanceId, enrichedDataSet, issuance.getCredentialFormat())
                )
                .doOnSuccess(v -> log.info("[{}] credential_accepted: issuanceId={} transitioned to ISSUED",
                        processId, issuanceId))
                .then(activateIfReady(processId, issuance))
                .onErrorResume(e -> {
                    log.warn("[{}] credential_accepted: failed to persist enriched data for issuanceId={}: {}",
                            processId, issuanceId, e.getMessage());
                    return Mono.empty();
                });
    }

    /**
     * If validFrom is null or already in the past, transition immediately from ISSUED to VALID
     * instead of waiting for the scheduled activation job.
     */
    private Mono<Void> activateIfReady(String processId, Issuance issuance) {
        Timestamp validFrom = issuance.getValidFrom();
        if (validFrom != null && validFrom.toInstant().isAfter(Instant.now())) {
            log.info("[{}] credential_accepted: issuanceId={} validFrom={} is in the future, staying ISSUED",
                    processId, issuance.getIssuanceId(), validFrom);
            return Mono.empty();
        }
        log.info("[{}] credential_accepted: issuanceId={} activating immediately (validFrom={})",
                processId, issuance.getIssuanceId(), validFrom);
        return issuanceService.updateIssuanceStatusToValidByIssuanceId(issuance.getIssuanceId().toString());
    }

    /**
     * credential_failure: notify user by email and stay in DRAFT. Wallet may retry.
     * Email errors are swallowed so the 204 response to the Wallet is never affected.
     */
    private Mono<Void> handleFailure(String processId, Issuance issuance, String eventDescription) {
        String issuanceId = issuance.getIssuanceId().toString();
        log.info("[{}] credential_failure: issuanceId={} stays in DRAFT. Sending failure notification email.",
                processId, issuanceId);
        return emailService.sendCredentialFailureNotification(issuance.getEmail(), eventDescription)
                .onErrorResume(EmailCommunicationException.class, e -> {
                    log.warn("[{}] credential_failure: could not send failure email for issuanceId={}",
                            processId, issuanceId, e);
                    return Mono.empty();
                })
                .onErrorResume(Exception.class, e -> {
                    log.error("[{}] credential_failure: UNEXPECTED BUG processing issuanceId={}",
                            processId, issuanceId, e);
                    return Mono.empty();
                });
    }

    /**
     * credential_deleted: DRAFT -> WITHDRAWN + revoke status list entry
     */
    private Mono<Void> handleDeleted(String processId, Issuance issuance, String bearerToken) {
        String issuanceId = issuance.getIssuanceId().toString();
        log.info("[{}] credential_deleted: withdrawing issuanceId={}", processId, issuanceId);

        return issuanceService.withdrawIssuance(issuanceId)
                .then(revokeCredentialFromDecoded(processId, issuance, bearerToken))
                .doOnSuccess(v -> log.info("[{}] credential_deleted: issuanceId={} withdrawn and status list entry revoked",
                        processId, issuanceId))
                .onErrorResume(e -> {
                    log.warn("[{}] credential_deleted: error processing issuanceId={}: {}",
                            processId, issuanceId, e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<Void> revokeCredentialFromDecoded(String processId, Issuance issuance, String bearerToken) {
        String issuanceId = issuance.getIssuanceId().toString();
        return revocationWorkflow.revokeSystem(processId, bearerToken, issuanceId)
                .doFirst(() -> log.info("processId={} action=revokeCredential status=started issuanceId={}",
                        processId, issuanceId))
                .doOnSuccess(v -> log.info("processId={} action=revokeCredential status=completed issuanceId={}",
                        processId, issuanceId))
                .doOnError(e -> log.warn("processId={} action=revokeCredential status=failed issuanceId={} error={}",
                        processId, issuanceId, e.getMessage(), e));
    }
}
