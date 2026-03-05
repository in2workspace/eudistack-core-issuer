package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.model.dto.PendingCredentials;
import es.in2.issuer.backend.shared.domain.model.dto.SignedCredentials;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeferredCredentialWorkflowImplTest {
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock
    private EmailService emailService;

    @InjectMocks
    private DeferredCredentialWorkflowImpl deferredCredentialWorkflow;

    @Test
    void getPendingCredentialsByOrganizationId(){
        String organizationId = "4321";
        String expectedCredential = "Credential1";
        PendingCredentials expectedPendingCredentials = PendingCredentials.builder()
                .credentials(List.of(PendingCredentials.CredentialPayload.builder()
                        .credential(expectedCredential)
                        .build()))
                .build();

        when(credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationId))
                .thenReturn(Flux.just(expectedCredential));

        StepVerifier.create(deferredCredentialWorkflow.getPendingCredentialsByOrganizationId(organizationId))
                .expectNext(expectedPendingCredentials)
                .verifyComplete();
    }

    @Test
    void updateSignedCredentials_shouldCallUpdateVcByProcedureId() {
        // given
        String procedureId = "1234";
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ2YyI6eyJpZCI6Im15SWQifX0.signature";

        SignedCredentials.SignedCredential signedCredential =
                SignedCredentials.SignedCredential.builder()
                        .credential(jwt)
                        .build();

        SignedCredentials signedCredentials =
                SignedCredentials.builder()
                        .credentials(List.of(signedCredential))
                        .build();

        when(deferredCredentialMetadataService.updateVcByProcedureId(jwt, procedureId))
                .thenReturn(Mono.empty());

        // when + then
        StepVerifier.create(deferredCredentialWorkflow.updateSignedCredentials(signedCredentials, procedureId))
                .verifyComplete();
    }
}
