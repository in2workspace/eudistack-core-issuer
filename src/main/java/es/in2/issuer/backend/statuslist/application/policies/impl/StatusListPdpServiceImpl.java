package es.in2.issuer.backend.statuslist.application.policies.impl;

import es.in2.issuer.backend.backoffice.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireOrganizationRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireRoleRule;
import es.in2.issuer.backend.statuslist.application.policies.StatusListPdpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListPdpServiceImpl implements StatusListPdpService {

    private final PolicyContextFactory policyContextFactory;

    @Override
    public Mono<Void> validateRevokeCredential(String processId,
                                               String token,
                                               CredentialProcedure procedure) {

        return Mono.defer(() -> {
            log.info("Process ID: {} - Validating 'revoke' action...", processId);
            return validateStatus(procedure.getCredentialStatus())
                    .then(Mono.defer(() -> policyContextFactory.fromTokenSimple(token)))
                    .flatMap(ctx -> {
                        RequireRoleRule<Void> roleRule = RequireRoleRule.of(LEAR);
                        return roleRule.evaluate(ctx, null)
                                .then(new RequireOrganizationRule()
                                        .evaluate(ctx, procedure.getOrganizationIdentifier()));
                    });
        });
    }

    @Override
    public Mono<Void> validateRevokeCredentialSystem(String processId, CredentialProcedure procedure) {
        return Mono.defer(() -> {
            log.info("Process ID: {} - Validating 'revoke' action (system)...", processId);
            return validateStatus(procedure.getCredentialStatus());
        });
    }

    private Mono<Void> validateStatus(CredentialStatusEnum credentialStatus) {
        if (credentialStatus == VALID) {
            return Mono.empty();
        }
        return Mono.error(
                new InvalidStatusException("Invalid status: " + credentialStatus)
        );
    }
}
