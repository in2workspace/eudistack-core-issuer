package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.statuslist.application.policies.StatusListPdpService;
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
    private final ProcedureService procedureService;
    private final EmailService emailService;
    private final AuditService auditService;

    private record RevocationContext(String token, CredentialProcedure procedure) { }

    @FunctionalInterface
    private interface RevocationValidator {
        Mono<Void> validate(String processId, String token, CredentialProcedure procedure);
    }

    @Observed(name = "revocation.revoke", contextualName = "revocation-revoke")
    public Mono<Void> revoke(String processId, String bearerToken, String credentialProcedureId) {
        return revokeInternal(
                processId,
                bearerToken,
                credentialProcedureId,
                statusListPdpService::validateRevokeCredential,
                "revokeCredential"
        );
    }

    @Observed(name = "revocation.revoke-system", contextualName = "revocation-revoke-system")
    public Mono<Void> revokeSystem(String processId, String bearerToken, String credentialProcedureId) {
        return revokeInternal(
                processId,
                bearerToken,
                credentialProcedureId,
                (pid, token, procedure) -> statusListPdpService.validateRevokeCredentialSystem(pid, procedure),
                "revokeSystemCredential"
        );
    }

    private Mono<Void> revokeInternal(
            String processId,
            String bearerToken,
            String credentialProcedureId,
            RevocationValidator validator,
            String action
    ) {
        requireNonNullParam(processId, "processId");
        requireNonNullParam(bearerToken, "bearerToken");
        requireNonNullParam(credentialProcedureId, "credentialProcedureId");

        return accessTokenService.getCleanBearerToken(bearerToken)
                .doFirst(() -> log.info(
                        "processId={} action={} status=started procedureId={}",
                        processId, action, credentialProcedureId
                ))
                .flatMap(token ->
                        procedureService.getProcedureById(credentialProcedureId)
                                .doOnSuccess(p -> log.debug(
                                        "processId={} action={} step=procedureLoaded procedureId={} credentialStatus={}",
                                        processId, action, credentialProcedureId, p != null ? p.getCredentialStatus() : null
                                ))
                                .flatMap(procedure ->
                                        validator.validate(processId, token, procedure)
                                                .doOnSuccess(v -> log.info(
                                                        "processId={} action={} step=validationPassed procedureId={}",
                                                        processId, action, credentialProcedureId
                                                ))
                                                .thenReturn(new RevocationContext(token, procedure))
                                )
                )
                .flatMap(ctx ->
                        statusListProvider.revoke(credentialProcedureId, ctx.token)
                                .then(procedureService.updateCredentialProcedureCredentialStatusToRevoke(ctx.procedure)
                                        .doOnSuccess(v -> log.info(
                                                "processId={} action={} step=procedureUpdated procedureId={}",
                                                processId, action, credentialProcedureId
                                        ))
                                )
                                .then(procedureService.extractCredentialId(ctx.procedure)
                                        .zipWith(procedureService.findCredentialOfferEmailInfoByProcedureId(credentialProcedureId))
                                        .flatMap(idAndInfo -> emailService.sendCredentialStatusChangeNotification(
                                                idAndInfo.getT2().email(),
                                                idAndInfo.getT2().organization(),
                                                idAndInfo.getT1(),
                                                ctx.procedure.getCredentialType(),
                                                REVOKED
                                        ))
                                        .doOnSuccess(v -> log.debug(
                                                "processId={} action={} step=emailNotificationTriggered procedureId={} newStatus={}",
                                                processId, action, credentialProcedureId, REVOKED
                                        ))
                                )
                )
                .doOnSuccess(v -> {
                    log.info("processId={} action={} status=completed procedureId={}",
                            processId, action, credentialProcedureId);
                    auditService.auditSuccess("credential.revoked", null, "credential", credentialProcedureId,
                            Map.of("processId", processId, "action", action));
                })
                .doOnError(e -> log.warn(
                        "processId={} action={} status=failed procedureId={} error={}",
                        processId, action, credentialProcedureId, e.toString()
                ));
    }
}
