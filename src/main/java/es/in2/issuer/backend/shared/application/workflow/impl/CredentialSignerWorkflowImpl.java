package es.in2.issuer.backend.shared.application.workflow.impl;


import es.in2.issuer.backend.shared.domain.service.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.application.workflow.DeferredCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.exception.Base45Exception;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureInvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.SignedCredentials;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.util.sdjwt.Disclosure;
import es.in2.issuer.backend.shared.domain.util.sdjwt.SdJwtPayloadBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl.minvws.encoding.Base45;
import org.apache.commons.compress.compressors.CompressorOutputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialSignerWorkflowImpl implements CredentialSignerWorkflow {

    private final AccessTokenService accessTokenService;
    private final BackofficePdpService backofficePdpService;
    private final ObjectMapper objectMapper;
    private final DeferredCredentialWorkflow deferredCredentialWorkflow;
    private final SigningProvider signingProvider;
    private final CredentialProcedureRepository credentialProcedureRepository;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final IssuerFactory issuerFactory;
    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final SdJwtPayloadBuilder sdJwtPayloadBuilder;


    @Observed(name = "issuance.sign-credential", contextualName = "issuance-sign-credential")
    @Override
    public Mono<String> signAndUpdateCredentialByProcedureId(String token, String procedureId, String format) {
        log.debug("signAndUpdateCredentialByProcedureId");

        return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    try {
                        String credentialType = credentialProcedure.getCredentialType();
                        String updatedBy = credentialProcedure.getUpdatedBy();
                        log.info("Building JWT payload for credential signing for credential with type: {}", credentialType);

                        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialType);
                        if (profile == null) {
                            log.error("Unsupported credential type: {}", credentialType);
                            return Mono.error(new IllegalArgumentException("Unsupported credential type: " + credentialType));
                        }

                        Mono<Map<String, Object>> cnfMono = profile.cnfRequired()
                                ? Mono.fromCallable(() -> parseCnfJson(credentialProcedure.getCnf()))
                                : Mono.just(Map.of());

                        // SD-JWT path: build flat payload directly from decoded credential
                        if (DC_SD_JWT.equals(format) && profile.sdJwt() != null) {
                            final CredentialProfile finalProfile = profile;
                            return cnfMono.flatMap(cnfMap ->
                                    buildSdJwtCredential(finalProfile, credentialProcedure.getCredentialDecoded(),
                                            cnfMap, token, procedureId, updatedBy)
                            );
                        }

                        return cnfMono.flatMap(cnfMap ->
                                genericCredentialBuilder.buildJwtPayload(
                                                profile,
                                                credentialProcedure.getCredentialDecoded(),
                                                profile.cnfRequired() ? cnfMap : null)
                                        .flatMap(unsignedCredential ->
                                                signCredentialOnRequestedFormat(unsignedCredential, format, token, procedureId, updatedBy)
                                        )
                        );
                    } catch (Exception e) {
                        log.error("Error signing credential with procedure id: {} - {}", procedureId, e.getMessage(), e);
                        return Mono.error(new IllegalArgumentException("Error signing credential"));
                    }
                })
                .flatMap(signedCredential -> {
                    log.info("Update Signed Credential");
                    return updateSignedCredential(signedCredential, procedureId)
                            .thenReturn(signedCredential);
                })
                .doOnSuccess(x -> log.info("Credential Signed and updated successfully."));
    }

    private Mono<Void> updateSignedCredential(String signedCredential, String procedureId) {
        List<SignedCredentials.SignedCredential> credentials = List.of(SignedCredentials.SignedCredential.builder().credential(signedCredential).build());
        SignedCredentials signedCredentials = new SignedCredentials(credentials);
        return deferredCredentialWorkflow.updateSignedCredentials(signedCredentials, procedureId);
    }

    private Mono<String> signCredentialOnRequestedFormat(String unsignedCredential, String format, String token, String procedureId, String email) {
        return Mono.defer(() -> {
            if (format.equals(JWT_VC_JSON)) {
                return setSubIfCredentialSubjectIdPresent(unsignedCredential)
                        .flatMap(payloadToSign -> {
                            log.info("Signing credential in JADES remotely ...");
                            SigningRequest signingRequest = SigningRequest.builder()
                                    .type(SigningType.JADES)
                                    .data(payloadToSign)
                                    .context(new SigningContext(token, procedureId, email))
                                    .build();

                            return signingProvider.sign(signingRequest)
                                    .map(SigningResult::data);
                        });

            } else if (format.equals(CWT_VC)) {
                log.info(unsignedCredential);
                return generateCborFromJson(unsignedCredential)
                        .flatMap(cbor -> generateCOSEBytesFromCBOR(cbor, token, email, procedureId))
                        .flatMap(this::compressAndConvertToBase45FromCOSE);
            } else {
                return Mono.error(new IllegalArgumentException("Unsupported credential format: " + format));
            }
        });
    }

    private java.util.Map<String, Object> parseCnfJson(String cnfJson) throws ParseCredentialJsonException{
        if (cnfJson == null || cnfJson.isBlank()) {
            throw new ParseCredentialJsonException("Missing cnf in CredentialProcedure");
        }
        try {
            return objectMapper.readValue(cnfJson, new TypeReference<Map<String, Object>>() {});
        } catch (JsonProcessingException _) {
            throw new ParseCredentialJsonException("Invalid cnf JSON");
        }
    }

    private Mono<String> setSubIfCredentialSubjectIdPresent(String unsignedCredential) {
        return Mono.fromCallable(() -> {
            JsonNode root = objectMapper.readTree(unsignedCredential);
            if (!(root instanceof ObjectNode rootObj)) {
                return unsignedCredential;
            }

            String subjectDid = extractSubjectDid(rootObj);

            if (subjectDid != null && !subjectDid.isBlank()) {
                rootObj.put("sub", subjectDid);
                return objectMapper.writeValueAsString(rootObj);
            }

            return unsignedCredential;
        })
        .subscribeOn(Schedulers.boundedElastic())
        .onErrorResume(e -> {
            log.warn(
                    "Could not set 'sub' from vc.credentialSubject.id. Keeping original payload. Reason: {}",
                    e.getMessage()
            );
            return Mono.just(unsignedCredential);
        });
    }

    private String extractSubjectDid(ObjectNode rootObj) {
        JsonNode csNode = rootObj.path("vc").path("credentialSubject");

        if (csNode.isObject()) {
            return extractIdFromObject(csNode);
        }

        if (csNode.isArray()) {
            return extractIdFromArray((ArrayNode) csNode);
        }

        return null;
    }

    private String extractIdFromObject(JsonNode csNode) {
        JsonNode idNode = csNode.path("id");
        return idNode.isTextual() ? idNode.asText() : null;
    }

    private String extractIdFromArray(ArrayNode arrayNode) {
        for (JsonNode item : arrayNode) {
            if (item != null && item.isObject()) {
                JsonNode idNode = item.path("id");
                if (idNode.isTextual() && !idNode.asText().isBlank()) {
                    return idNode.asText();
                }
            }
        }
        return null;
    }

    /**
     * Generate CBOR payload for COSE.
     *
     * @param edgcJson EDGC payload as JSON string
     * @return Mono emitting CBOR bytes
     */
    private Mono<byte[]> generateCborFromJson(String edgcJson) {
        return Mono.fromCallable(() -> CBORObject.FromJSONString(edgcJson).EncodeToBytes());
    }

    /**
     * Generate COSE bytes from CBOR bytes.
     *
     * @param cbor  CBOR bytes
     * @param token Authentication token
     * @return Mono emitting COSE bytes
     */
    private Mono<byte[]> generateCOSEBytesFromCBOR(byte[] cbor, String token, String email, String procedureId) {
        log.info("Signing credential in COSE format remotely ...");
        String cborBase64 = Base64.getEncoder().encodeToString(cbor);
        SigningRequest signingRequest = SigningRequest.builder()
                .type(SigningType.COSE)
                .data(cborBase64)
                .context(new SigningContext(token, procedureId, email))
                .build();
        return signingProvider.sign(signingRequest)
                .map(SigningResult::data)
                .map(Base64.getDecoder()::decode);
    }

    /**
     * Compress COSE bytes and convert it to Base45.
     *
     * @param cose COSE Bytes
     * @return Mono emitting COSE bytes compressed and in Base45
     */
    private Mono<String> compressAndConvertToBase45FromCOSE(byte[] cose) {
        return Mono.fromCallable(() -> {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            try (CompressorOutputStream deflateOut = new CompressorStreamFactory()
                    .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, stream)) {
                deflateOut.write(cose);
            } // Automatically closed by try-with-resources
            byte[] zip = stream.toByteArray();
            return Base45.getEncoder().encodeToString(zip);
        }).onErrorResume(e -> {
            log.error("Error compressing and converting to Base45: " + e.getMessage(), e);
            return Mono.error(new Base45Exception("Error compressing and converting to Base45"));
        });
    }

    @Override
    public Mono<Void> retrySignUnsignedCredential(String processId, String authorizationHeader, String procedureId) {
        log.info("Retrying to sign credential. processId={} procedureId={}", processId, procedureId);

        return accessTokenService.getCleanBearerToken(authorizationHeader)
                .flatMap(token ->
                        backofficePdpService.validateSignCredential(processId, token, procedureId)
                                .then(Mono.just(token))
                                .zipWhen(t -> accessTokenService.getMandateeEmail(authorizationHeader))
                )
                .flatMap(tupleTokenEmail -> {
                    String token = tupleTokenEmail.getT1();
                    String email = tupleTokenEmail.getT2();

                    return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                            .switchIfEmpty(Mono.error(new CredentialProcedureNotFoundException(
                                    "Credential procedure with ID " + procedureId + " was not found"
                            )))
                            .doOnNext(credentialProcedure ->
                                    log.info("ProcessID: {} - Current credential status: {}",
                                            processId, credentialProcedure.getCredentialStatus())
                            )
                            .filter(credentialProcedure ->
                                    credentialProcedure.getCredentialStatus() == CredentialStatusEnum.PEND_SIGNATURE
                            )
                            .switchIfEmpty(Mono.error(new CredentialProcedureInvalidStatusException(
                                    "Credential procedure with ID " + procedureId + " is not in PEND_SIGNATURE status"
                            )))
                            .flatMap(credentialProcedure -> {
                                String configId = credentialProcedure.getCredentialType();

                                CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
                                if (profile == null) {
                                    log.error("Unknown credential type: {}", configId);
                                    return Mono.error(new IllegalArgumentException(
                                            "Unsupported credential type: " + configId));
                                }

                                Mono<Void> updateDecodedCredentialMono = genericCredentialBuilder
                                        .bindIssuer(profile, credentialProcedure.getCredentialDecoded(), procedureId, email)
                                        .flatMap(bindCredential -> updateDecodedCredentialByProcedureId(procedureId, bindCredential));

                                return updateDecodedCredentialMono
                                        .then(this.signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC_JSON))
                                        .flatMap(signedVc ->
                                                credentialProcedureService
                                                        .updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId)
                                                        .thenReturn(signedVc)
                                        )
                                        .flatMap(signedVc ->
                                                credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                                                        .flatMap(updatedCredentialProcedure ->
                                                                credentialProcedureRepository.save(updatedCredentialProcedure)
                                                                        .thenReturn(updatedCredentialProcedure)
                                                        )
                                                        .then(Mono.<Void>empty())
                                        );
                            });
                })
                .then();
    }

    private Mono<String> buildSdJwtCredential(CredentialProfile profile, String decodedCredentialJson,
            Map<String, Object> cnfMap, String token, String procedureId, String email) {
        return Mono.fromCallable(() -> sdJwtPayloadBuilder.build(decodedCredentialJson, profile, cnfMap))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(components -> {
                    log.info("Signing SD-JWT credential for procedureId={}", procedureId);
                    SigningRequest signingRequest = SigningRequest.builder()
                            .type(SigningType.JADES)
                            .data(components.payloadJson())
                            .context(new SigningContext(token, procedureId, email))
                            .typ(DC_SD_JWT)
                            .build();
                    return signingProvider.sign(signingRequest)
                            .map(result -> {
                                StringBuilder sb = new StringBuilder(result.data());
                                for (Disclosure d : components.disclosures()) {
                                    sb.append('~').append(d.encoded());
                                }
                                sb.append('~');
                                return sb.toString();
                            });
                });
    }

    private Mono<Void> updateDecodedCredentialByProcedureId(String procedureId, String bindCredential) {
        log.info("ProcessID: {} - Credential mapped and bound to the issuer: {}", procedureId, bindCredential);
        return credentialProcedureService.updateDecodedCredentialByProcedureId(
                procedureId,
                bindCredential,
                JWT_VC_JSON
        );
    }
}
