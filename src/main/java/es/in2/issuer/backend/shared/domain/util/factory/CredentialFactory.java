package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
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
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;

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

    public Mono<String> bindCryptographicCredentialSubjectId(
            String processId,
            String credentialType,
            String decodedCredential,
            String subjectDid) {

        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialType);
        if (profile == null) profile = credentialProfileRegistry.getByCredentialType(credentialType);
        if (profile == null) {
            return Mono.error(new CredentialTypeUnsupportedException(credentialType));
        }
        return genericCredentialBuilder.bindSubjectId(profile, decodedCredential, subjectDid)
                .doOnSuccess(bound ->
                        log.info("ProcessID: {} - Credential bound to subject via profile: {}", processId, credentialType));
    }


    public Mono<Void> mapCredentialBindIssuerAndUpdateDB(
            String processId,
            String procedureId,
            String decodedCredential,
            String credentialType,
            String format,
            String authServerNonce,
            String email) {

        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialType);
        if (profile == null) profile = credentialProfileRegistry.getByCredentialType(credentialType);
        if (profile == null) {
            return Mono.error(new CredentialTypeUnsupportedException(credentialType));
        }
        Mono<String> bindMono = genericCredentialBuilder.bindIssuer(profile, decodedCredential, procedureId, email);

        return bindMono
                .flatMap(boundCredential -> {
                    log.info("ProcessID: {} - Credential mapped and bind to the issuer: {}", processId, boundCredential);
                    return updateDecodedAndDeferred(procedureId, boundCredential, format, authServerNonce);
                });
    }

    private Mono<Void> updateDecodedAndDeferred(
            String procedureId,
            String boundCredential,
            String format,
            String authServerNonce) {
        return credentialProcedureService
                .updateCredentialDataSetByProcedureId(procedureId, boundCredential, format)
                .then(deferredCredentialMetadataService.updateDeferredCredentialByAuthServerNonce(authServerNonce, format)
                );
    }
}
