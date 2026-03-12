package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.policy.service.StatusListPdpService;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.REVOKED;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@Slf4j
@Service
@RequiredArgsConstructor
public class RevocationWorkflow {

    private final StatusListProvider statusListProvider;
    private final AccessTokenService accessTokenService;
    private final StatusListPdpService statusListPdpService;
    private final IssuanceService issuanceService;
    private final EmailService emailService;
    private final AuditService auditService;

    private record RevocationContext(String token, Issuance issuance) { }

    @FunctionalInterface
    private interface RevocationValidator {
        Mono<Void> validate(String processId, String token, Issuance issuance);
    }

    @Observed(name = "revocation.revoke", contextualName = "revocation-revoke")
    public Mono<Void> revoke(String processId, String bearerToken, String issuanceId) {
        return revokeInternal(
                processId,
                bearerToken,
                issuanceId,
                statusListPdpService::validateRevokeCredential,
                "revokeCredential"
        );
    }

    @Observed(name = "revocation.revoke-system", contextualName = "revocation-revoke-system")
    public Mono<Void> revokeSystem(String processId, String bearerToken, String issuanceId) {
        return revokeInternal(
                processId,
                bearerToken,
                issuanceId,
                (pid, token, issuance) -> statusListPdpService.validateRevokeCredentialSystem(pid, issuance),
                "revokeSystemCredential"
        );
    }

    private Mono<Void> revokeInternal(
            String processId,
            String bearerToken,
            String issuanceId,
            RevocationValidator validator,
            String action
    ) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(bearerToken, "bearerToken");
        requireNonNullParam(issuanceId, "issuanceId");

        return accessTokenService.getCleanBearerToken(bearerToken)
                .doFirst(() -> log.info(
                        "processId={} action={} status=started issuanceId={}",
                        processId, action, issuanceId
                ))
                .flatMap(token ->
                        issuanceService.getIssuanceById(issuanceId)
                                .doOnSuccess(p -> log.debug(
                                        "processId={} action={} step=issuanceLoaded issuanceId={} credentialStatus={}",
                                        processId, action, issuanceId, p != null ? p.getCredentialStatus() : null
                                ))
                                .flatMap(issuance ->
                                        validator.validate(processId, token, issuance)
                                                .doOnSuccess(v -> log.info(
                                                        "processId={} action={} step=validationPassed issuanceId={}",
                                                        processId, action, issuanceId
                                                ))
                                                .thenReturn(new RevocationContext(token, issuance))
                                )
                )
                .flatMap(ctx ->
                        statusListProvider.revoke(issuanceId, ctx.token)
                                .then(issuanceService.updateIssuanceStatusToRevoked(ctx.issuance)
                                        .doOnSuccess(v -> log.info(
                                                "processId={} action={} step=issuanceUpdated issuanceId={}",
                                                processId, action, issuanceId
                                        ))
                                )
                                .then(issuanceService.extractCredentialId(ctx.issuance)
                                        .defaultIfEmpty(issuanceId)
                                        .flatMap(credentialId -> emailService.sendCredentialStatusChangeNotification(
                                                ctx.issuance.getEmail(),
                                                credentialId,
                                                ctx.issuance.getCredentialType(),
                                                REVOKED
                                        ))
                                        .doOnSuccess(v -> log.debug(
                                                "processId={} action={} step=emailNotificationTriggered issuanceId={} newStatus={}",
                                                processId, action, issuanceId, REVOKED
                                        ))
                                        .onErrorResume(e -> {
                                            log.warn(
                                                    "processId={} action={} step=emailNotificationFailed issuanceId={} error={}",
                                                    processId, action, issuanceId, e.toString()
                                            );
                                            return Mono.empty();
                                        })
                                )
                )
                .doOnSuccess(v -> {
                    log.info("processId={} action={} status=completed issuanceId={}",
                            processId, action, issuanceId);
                    auditService.auditSuccess("credential.revoked", null, "credential", issuanceId,
                            Map.of("processId", processId, "action", action));
                })
                .doOnError(e -> log.warn(
                        "processId={} action={} status=failed issuanceId={} error={}",
                        processId, action, issuanceId, e.toString()
                ));
    }
}
