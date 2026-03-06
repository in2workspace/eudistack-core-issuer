package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Slf4j
public class CredentialFactory {

    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialProfileRegistry credentialProfileRegistry;

    public Mono<CredentialProcedureCreationRequest> mapCredentialIntoACredentialProcedureRequest(String processId, String procedureId, PreSubmittedCredentialDataRequest preSubmittedCredentialRequest, CredentialStatus credentialStatus, String email) {
        log.info("mapCredentialIntoACredentialProcedureRequest - preSubmittedCredentialRequest:{} - credentialStatus:{}", preSubmittedCredentialRequest, credentialStatus);
        String credentialConfigurationId = preSubmittedCredentialRequest.credentialConfigurationId();
        JsonNode credential = preSubmittedCredentialRequest.payload();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        if (profile == null) profile = credentialProfileRegistry.getByCredentialType(credentialConfigurationId);
        if (profile == null) {
            return Mono.error(new CredentialTypeUnsupportedException(credentialConfigurationId));
        }
        return genericCredentialBuilder.buildCredential(profile, procedureId, credential, credentialStatus, email)
                .doOnSuccess(result -> log.info("ProcessID: {} - Credential mapped via profile: {}", processId, credentialConfigurationId));
    }

}
