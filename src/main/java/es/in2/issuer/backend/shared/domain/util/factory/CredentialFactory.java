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

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Component
@RequiredArgsConstructor
@Slf4j
public class CredentialFactory {

    public final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    public final LEARCredentialMachineFactory learCredentialMachineFactory;
    public final LabelCredentialFactory labelCredentialFactory;
    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;

    public Mono<CredentialProcedureCreationRequest> mapCredentialIntoACredentialProcedureRequest(String processId, String procedureId, PreSubmittedCredentialDataRequest preSubmittedCredentialRequest, CredentialStatus credentialStatus, String email) {
        log.info("mapCredentialIntoACredentialProcedureRequest - preSubmittedCredentialRequest:{} - credentialStatus:{}", preSubmittedCredentialRequest, credentialStatus);
        String credentialConfigurationId = preSubmittedCredentialRequest.credentialConfigurationId();
        JsonNode credential = preSubmittedCredentialRequest.payload();
        String operationMode = preSubmittedCredentialRequest.operationMode();

        // Try profile-based generic path (configId first for unambiguous lookup, then credentialType fallback)
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        if (profile == null) profile = credentialProfileRegistry.getByCredentialType(credentialConfigurationId);
        if (profile != null) {
            return genericCredentialBuilder.buildCredential(profile, procedureId, credential, credentialStatus, operationMode, email)
                    .doOnSuccess(result -> log.info("ProcessID: {} - Credential mapped via profile: {}", processId, credentialConfigurationId));
        }

        // Fallback to old factories
        if (credentialConfigurationId.equals(LEAR_CREDENTIAL_EMPLOYEE)) {
            return learCredentialEmployeeFactory.mapAndBuildLEARCredentialEmployee(procedureId, credential, credentialStatus, operationMode, email)
                    .doOnSuccess(learCredentialEmployee -> log.info("ProcessID: {} - LEARCredentialEmployee mapped: {}", processId, credential));
        } else if (credentialConfigurationId.equals(LABEL_CREDENTIAL)) {
            return labelCredentialFactory.mapAndBuildLabelCredential(procedureId, credential, credentialStatus, operationMode, email)
                    .doOnSuccess(verifiableCertification -> log.info("ProcessID: {} - Label Credential mapped: {}", processId, credential));
        } else if (credentialConfigurationId.equals(LEAR_CREDENTIAL_MACHINE)) {
            return learCredentialMachineFactory.mapAndBuildLEARCredentialMachine(procedureId, credential, credentialStatus, operationMode, email)
                    .doOnSuccess(learCredentialMachine -> log.info("ProcessID: {} - LEARCredentialMachine mapped: {}", processId, credential));
        }
        return Mono.error(new CredentialTypeUnsupportedException(credentialConfigurationId));
    }

    public Mono<String> bindCryptographicCredentialSubjectId(
            String processId,
            String credentialType,
            String decodedCredential,
            String subjectDid) {

        // Try profile-based generic path (configId → credentialType fallback)
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialType);
        if (profile == null) profile = credentialProfileRegistry.getByCredentialType(credentialType);
        if (profile != null) {
            return genericCredentialBuilder.bindSubjectId(decodedCredential, subjectDid)
                    .doOnSuccess(bound ->
                            log.info("ProcessID: {} - Credential bound to subject via profile: {}", processId, credentialType));
        }

        // Fallback to old factories
        if (credentialType.equals(LEAR_CREDENTIAL_EMPLOYEE)) {
            return learCredentialEmployeeFactory
                    .bindCryptographicCredentialSubjectId(decodedCredential, subjectDid)
                    .doOnSuccess(bound ->
                            log.info("ProcessID: {} - LEARCredentialEmployee mapped and bind to the id: {}", processId, bound));
        } else if (credentialType.equals(LEAR_CREDENTIAL_MACHINE)) {
            return learCredentialMachineFactory
                    .bindCryptographicCredentialSubjectId(decodedCredential, subjectDid)
                    .doOnSuccess(bound ->
                            log.info("ProcessID: {} - LEARCredentialMachine mapped and bind to the id: {}", processId, bound));
        }

        return Mono.error(new CredentialTypeUnsupportedException(credentialType));
    }


    public Mono<Void> mapCredentialBindIssuerAndUpdateDB(
            String processId,
            String procedureId,
            String decodedCredential,
            String credentialType,
            String format,
            String authServerNonce,
            String email) {

        // Try profile-based generic path (configId → credentialType fallback)
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialType);
        if (profile == null) profile = credentialProfileRegistry.getByCredentialType(credentialType);
        Mono<String> bindMono;

        if (profile != null) {
            bindMono = genericCredentialBuilder.bindIssuer(profile, decodedCredential, procedureId, email);
        } else {
            // Fallback to old factories
            bindMono = switch (credentialType) {
                case LEAR_CREDENTIAL_EMPLOYEE ->
                        learCredentialEmployeeFactory
                                .mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId, email);
                case LABEL_CREDENTIAL ->
                        labelCredentialFactory
                                .mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId, email);
                case LEAR_CREDENTIAL_MACHINE ->
                        learCredentialMachineFactory
                                .mapCredentialAndBindIssuerInToTheCredential(decodedCredential, procedureId, email);
                default ->
                        Mono.error(new CredentialTypeUnsupportedException(credentialType));
            };
        }

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
                .updateDecodedCredentialByProcedureId(procedureId, boundCredential, format)
                .then(deferredCredentialMetadataService.updateDeferredCredentialByAuthServerNonce(authServerNonce, format)
                );
    }
}
