package es.in2.issuer.backend.shared.application.workflow.impl;

import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.application.workflow.DeferredCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.PendingCredentials;
import es.in2.issuer.backend.shared.domain.model.dto.SignedCredentials;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;



@Slf4j
@Service
@RequiredArgsConstructor
public class DeferredCredentialWorkflowImpl implements DeferredCredentialWorkflow {

    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final EmailService emailService;

    @Override
    public Mono<PendingCredentials> getPendingCredentialsByOrganizationId(String organizationId) {
        return credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationId)
                .map(decodedCredential -> PendingCredentials.CredentialPayload.builder()
                        .credential(decodedCredential)
                        .build())
                .collectList()
                .map(PendingCredentials::new);
    }

    @Override
    public Mono<Void> updateSignedCredentials(SignedCredentials signedCredentials, String procedureId) {
        return Flux.fromIterable(signedCredentials.credentials())
                .flatMap(sc -> processCredential(sc.credential(), procedureId))
                .then();
    }

    private Mono<Void> processCredential(String jwt, String procedureId) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            log.debug("Credential payload: {}", signedJWT.getPayload());

            return deferredCredentialMetadataService.updateVcByProcedureId(jwt, procedureId);
        } catch (Exception e) {
            return Mono.error(new RuntimeException("Failed to process signed credential", e));
        }
    }
}
