package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.shared.domain.exception.CredentialIssuanceException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.VerifiableCredentialService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;
import java.util.NoSuchElementException;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;


@Service
@RequiredArgsConstructor
@Slf4j
public class VerifiableCredentialServiceImpl implements VerifiableCredentialService {
    private final CredentialFactory credentialFactory;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    private final LabelCredentialFactory labelCredentialFactory;
    private final IssuerFactory issuerFactory;

    @Override
    public Mono<String> generateVc(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String email, CredentialStatus credentialStatus, String procedureId) {
        return credentialFactory.mapCredentialIntoACredentialProcedureRequest(
                        processId,
                        procedureId,
                        preSubmittedCredentialDataRequest,
                        credentialStatus,
                        email
                )
                .flatMap(credentialProcedureService::createCredentialProcedure)
                .then(deferredCredentialMetadataService.createDeferredCredentialMetadata(
                        procedureId,
                        preSubmittedCredentialDataRequest.operationMode(),
                        preSubmittedCredentialDataRequest.responseUri())
                )
                .flatMap(transactionCode ->
                        credentialProcedureService.updateFormatByProcedureId(procedureId, preSubmittedCredentialDataRequest.format())
                                .then(deferredCredentialMetadataService.updateFormatByProcedureId(procedureId, preSubmittedCredentialDataRequest.format()))
                                .thenReturn(transactionCode)
                );
    }

    @Override
    public Mono<CredentialResponse> generateDeferredCredentialResponse(CredentialProcedure procedure, String transactionId) {
        if (procedure.getCredentialStatus().equals(CredentialStatusEnum.VALID)) {
            return Mono.just(
                    CredentialResponse.builder()
                            .credentials(List.of(
                                    CredentialResponse.Credential.builder()
                                            .credential(procedure.getCredentialEncoded())
                                            .build()))
                            .build());
        } else {
            return Mono.just(CredentialResponse.builder()
                    .transactionId(transactionId)
                    .interval(DEFERRED_CREDENTIAL_POLLING_INTERVAL)
                    .build());
        }
    }

    @Override
    public Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, String accessToken, String preAuthCode) {
        try {
            JWSObject jwsObject = JWSObject.parse(accessToken);
            String newAuthServerNonce = jwsObject.getPayload().toJSONObject().get("jti").toString();
            return deferredCredentialMetadataService.updateAuthServerNonceByAuthServerNonce(newAuthServerNonce, preAuthCode);
        } catch (ParseException e) {
            throw new JWTParsingException("Failed to parse access token JWT");
        }

    }

    @Override
    public Mono<CredentialResponse> buildCredentialResponse(
            String processId,
            String subjectDid,
            String authServerNonce,
            String email,
            String procedureId){
        return bindAndSaveIfNeeded(processId, procedureId, subjectDid)
                .flatMap(boundCred -> updateDeferredAndMap(
                        processId,
                        procedureId,
                        boundCred,
                        authServerNonce,
                        email
                ));
    }

    private Mono<String> bindAndSaveIfNeeded(
            String processId,
            String procedureId,
            String subjectDid) {

        return Mono.zip(
                        credentialProcedureService.getCredentialTypeByProcedureId(procedureId),
                        credentialProcedureService.getDecodedCredentialByProcedureId(procedureId)
                )
                .flatMap(tuple -> {
                    String credentialType = tuple.getT1();
                    String decodedCredential = tuple.getT2();
                    if (subjectDid == null) {
                        return Mono.just(decodedCredential);
                    }

                    return credentialFactory
                            .bindCryptographicCredentialSubjectId(
                                    processId,
                                    credentialType,
                                    decodedCredential,
                                    subjectDid)
                            .onErrorResume(e -> {
                                log.error("Error binding cryptographic credential subject ID: {}", e.getMessage(), e);
                                return Mono.error(new CredentialIssuanceException("Failed to bind cryptographic credential subject", e));
                            })
                            .flatMap(bound -> credentialProcedureService
                                    .updateDecodedCredentialByProcedureId(procedureId, bound)
                                    .thenReturn(bound)
                            );

                });
    }
    private Mono<CredentialResponse> updateDeferredAndMap(
            String processId,
            String procedureId,
            String boundCredential,
            String authServerNonce,
            String email
    ) {
        return Mono.zip(
                        credentialProcedureService.getCredentialTypeByProcedureId(procedureId),
                        credentialProcedureService.getNotificationIdByProcedureId(procedureId)
                )
                .flatMap(tuple -> {
                    String credentialType = tuple.getT1();
                    String notificationId = tuple.getT2();
                    return deferredCredentialMetadataService
                            .updateDeferredCredentialMetadataByAuthServerNonce(authServerNonce)
                            .onErrorResume(e -> {
                                log.error("Error updating deferred metadata with authServerNonce: {}", e.getMessage(), e);
                                return Mono.error(new CredentialIssuanceException("Failed to update deferred metadata", e));
                            })
                            .switchIfEmpty(Mono.error(new NoSuchElementException("TransactionId not found after updating deferred metadata")))
                            .flatMap(transactionId -> deferredCredentialMetadataService.getFormatByProcedureId(procedureId)
                                    .onErrorResume(e -> {
                                        log.error("Error mapping/binding issuer and updating credential: {}", e.getMessage(), e);
                                        return Mono.error(new CredentialIssuanceException("Failed to retrieve credential format", e));
                                    })
                                    .switchIfEmpty(Mono.error(new NoSuchElementException("Credential format not found for procedureId: " + procedureId)))
                                    .flatMap(format -> credentialFactory
                                            .mapCredentialBindIssuerAndUpdateDB(
                                                    processId,
                                                    procedureId,
                                                    boundCredential,
                                                    credentialType,
                                                    format,
                                                    authServerNonce,
                                                    email
                                            )
                                            .then(getCredentialResponseWithTransactionId(transactionId, notificationId))
                                    )
                            );
                });
    }

    private Mono<CredentialResponse> getCredentialResponseWithTransactionId(String transactionId, String notificationId) {
        return Mono.just(
                CredentialResponse.builder()
                        .transactionId(transactionId)
                        .interval(DEFERRED_CREDENTIAL_POLLING_INTERVAL)
                        .notificationId(notificationId)
                        .build()
        );
    }

}
