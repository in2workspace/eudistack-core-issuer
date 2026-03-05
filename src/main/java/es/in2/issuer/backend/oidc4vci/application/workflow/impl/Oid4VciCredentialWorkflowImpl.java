package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.oidc4vci.application.workflow.Oid4VciCredentialWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.BindingInfo;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.ProofValidationService;
import es.in2.issuer.backend.shared.domain.service.VerifiableCredentialService;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.naming.ConfigurationException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.PEND_SIGNATURE;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class Oid4VciCredentialWorkflowImpl implements Oid4VciCredentialWorkflow {

    private final VerifiableCredentialService verifiableCredentialService;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final ProofValidationService proofValidationService;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final CredentialIssuerMetadataService credentialIssuerMetadataService;
    private final ObjectMapper objectMapper;

    @Override
    @Observed(name = "oid4vci.generate-vc-response", contextualName = "oid4vci-generate-vc-response")
    public Mono<CredentialResponse> generateVerifiableCredentialResponse(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext) {

        final String nonce = accessTokenContext.jti();
        final String procedureId = accessTokenContext.procedureId();

        return credentialProcedureService.getCredentialProcedureById(procedureId)
                .zipWhen(proc -> credentialIssuerMetadataService.getCredentialIssuerMetadata(processId))
                .flatMap(tuple -> {
                    CredentialProcedure proc = tuple.getT1();
                    CredentialIssuerMetadata md = tuple.getT2();
                    String email = proc.getEmail();

                    log.info("[{}] Loaded procedure: nonce={}, procedureId={}, type={}",
                            processId, nonce, procedureId, proc.getCredentialType());

                    Mono<BindingInfo> bindingInfoMono = validateAndDetermineBindingInfo(proc, md, credentialRequest)
                            .doOnNext(bi -> log.info("[{}] Binding: subjectId={}", processId, bi.subjectId()));

                    Mono<CredentialResponse> vcMono = bindingInfoMono
                            .flatMap(bi -> storeCnfIfPresent(procedureId, bi)
                                    .then(verifiableCredentialService.buildCredentialResponse(
                                            processId, bi.subjectId(), nonce, email, procedureId
                                    )))
                            .switchIfEmpty(Mono.defer(() -> verifiableCredentialService.buildCredentialResponse(
                                    processId, null, nonce, email, procedureId
                            )));

                    return vcMono.flatMap(cr ->
                            signAndDeliverCredential(processId, cr, proc, accessTokenContext.rawToken())
                    );
                });
    }

    @Override
    @Observed(name = "oid4vci.generate-deferred-response", contextualName = "oid4vci-generate-deferred-response")
    public Mono<CredentialResponse> generateVerifiableCredentialDeferredResponse(
            String processId,
            DeferredCredentialRequest deferredCredentialRequest,
            AccessTokenContext accessTokenContext) {

        String transactionId = deferredCredentialRequest.transactionId();
        log.debug("ProcessID: {} Generating deferred response for transactionId: {}", processId, transactionId);

        return deferredCredentialMetadataService.getDeferredCredentialMetadataByAuthServerNonce(accessTokenContext.jti())
                .flatMap(deferred ->
                        credentialProcedureService.getCredentialProcedureById(deferred.getProcedureId().toString())
                                .flatMap(procedure ->
                                        verifiableCredentialService.generateDeferredCredentialResponse(procedure, transactionId)));
    }

    @Override
    public Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, AuthServerNonceRequest authServerNonceRequest) {
        return verifiableCredentialService.bindAccessTokenByPreAuthorizedCode(
                processId, authServerNonceRequest.accessToken(), authServerNonceRequest.preAuthorizedCode());
    }

    private Mono<BindingInfo> validateAndDetermineBindingInfo(
            CredentialProcedure credentialProcedure,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest) {

        return resolveConfigurationId(credentialProcedure)
                .flatMap(configId -> findIssuerConfig(metadata, configId)
                        .flatMap(cfg -> evaluateCryptographicBinding(cfg, configId, metadata, credentialRequest))
                );
    }

    private Mono<String> resolveConfigurationId(CredentialProcedure credentialProcedure) {
        String configId = credentialProcedure.getCredentialType();
        if (configId == null || configId.isBlank()) {
            return Mono.error(new FormatUnsupportedException("Missing credential type in procedure"));
        }
        return Mono.just(configId);
    }

    private Mono<CredentialIssuerMetadata.CredentialConfiguration> findIssuerConfig(
            CredentialIssuerMetadata metadata, String configId) {
        return Mono.justOrEmpty(metadata.credentialConfigurationsSupported().get(configId))
                .switchIfEmpty(Mono.error(new FormatUnsupportedException(
                        "No configuration for configId: " + configId)));
    }

    private Mono<BindingInfo> evaluateCryptographicBinding(
            CredentialIssuerMetadata.CredentialConfiguration cfg,
            String credentialType,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest) {

        var cryptoMethods = cfg.cryptographicBindingMethodsSupported();
        boolean needsProof = cryptoMethods != null && !cryptoMethods.isEmpty();
        log.info("Binding requirement for {}: needsProof={}", credentialType, needsProof);

        if (!needsProof) {
            return Mono.empty();
        }

        String cryptoBindingMethod = cryptoMethods.stream()
                .findFirst()
                .orElseThrow(() -> new InvalidCredentialFormatException(
                        "No cryptographic binding method configured for " + credentialType));

        log.debug("Crypto binding method for {}: {}", credentialType, cryptoBindingMethod);

        Set<String> proofSigningAlgs = resolveProofSigningAlgorithms(cfg);
        String jwtProof = extractFirstJwtProof(credentialRequest);
        String expectedAudience = metadata.credentialIssuer();

        return validateProofAndExtractBindingInfo(jwtProof, proofSigningAlgs, expectedAudience, credentialType);
    }

    private Set<String> resolveProofSigningAlgorithms(CredentialIssuerMetadata.CredentialConfiguration cfg) {
        var proofTypes = cfg.proofTypesSupported();
        var jwtProofConfig = (proofTypes != null) ? proofTypes.get("jwt") : null;
        return (jwtProofConfig != null) ? jwtProofConfig.proofSigningAlgValuesSupported() : null;
    }

    private String extractFirstJwtProof(CredentialRequest credentialRequest) {
        return credentialRequest.proof() != null ? credentialRequest.proof().jwt() : null;
    }

    private Mono<BindingInfo> validateProofAndExtractBindingInfo(
            String jwtProof,
            Set<String> proofSigningAlgs,
            String expectedAudience,
            String credentialType) {

        if (proofSigningAlgs == null || proofSigningAlgs.isEmpty()) {
            return Mono.error(new ConfigurationException(
                    "No proof_signing_alg_values_supported for credential type " + credentialType));
        }

        if (jwtProof == null) {
            return Mono.error(new InvalidOrMissingProofException(
                    "Missing proof for type " + credentialType));
        }

        return proofValidationService.isProofValid(jwtProof, proofSigningAlgs, expectedAudience)
                .flatMap(valid -> {
                    if (!Boolean.TRUE.equals(valid)) {
                        return Mono.error(new InvalidOrMissingProofException("Invalid proof"));
                    }
                    return extractBindingInfoFromJwtProof(jwtProof);
                });
    }

    private Mono<Void> storeCnfIfPresent(String procedureId, BindingInfo bindingInfo) {
        if (bindingInfo.cnf() == null) {
            return Mono.empty();
        }
        return Mono.fromCallable(() -> objectMapper.writeValueAsString(bindingInfo.cnf()))
                .flatMap(cnfJson -> deferredCredentialMetadataService.updateCnfByProcedureId(procedureId, cnfJson));
    }

    private Mono<CredentialResponse> signAndDeliverCredential(
            String processId,
            CredentialResponse cr,
            CredentialProcedure proc,
            String rawToken) {

        return credentialProcedureService.getCredentialStatusByProcedureId(proc.getProcedureId().toString())
                .flatMap(status -> {
                    Mono<Void> upd = !PEND_SIGNATURE.toString().equals(status)
                            ? credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(
                                    proc.getProcedureId().toString())
                            : Mono.empty();

                    String credentialFormat = proc.getCredentialFormat() != null
                            ? proc.getCredentialFormat()
                            : JWT_VC_JSON;

                    return upd.then(
                            credentialSignerWorkflow.signAndUpdateCredentialByProcedureId(
                                            BEARER_PREFIX + rawToken,
                                            proc.getProcedureId().toString(),
                                            credentialFormat
                                    )
                                    .map(signedCredential -> CredentialResponse.builder()
                                            .credentials(List.of(CredentialResponse.Credential.builder()
                                                    .credential(signedCredential)
                                                    .build()))
                                            .build())
                                    .onErrorResume(e -> {
                                        if (e instanceof RemoteSignatureException || e instanceof IllegalArgumentException) {
                                            log.warn("[{}] Signing failed ({}), falling back to deferred", processId, e.getMessage());
                                            return Mono.just(cr);
                                        }
                                        return Mono.error(e);
                                    })
                    );
                });
    }

    private Mono<BindingInfo> extractBindingInfoFromJwtProof(String jwtProof) {
        return Mono.fromCallable(() -> {
            JWSObject jws = JWSObject.parse(jwtProof);
            var header = jws.getHeader().toJSONObject();

            Object kid = header.get("kid");
            Object jwk = header.get("jwk");
            Object x5c = header.get("x5c");

            int count = (kid != null ? 1 : 0) + (jwk != null ? 1 : 0) + (x5c != null ? 1 : 0);
            if (count != 1) {
                throw new ProofValidationException("Expected exactly one of kid/jwk/x5c in proof header");
            }

            if (kid != null) {
                return buildFromKid(kid);
            } else if (x5c != null) {
                throw new ProofValidationException("x5c not supported yet");
            } else if (jwk != null) {
                return buildFromJwk(jwk);
            }

            throw new ProofValidationException("No key material found in proof header");
        });
    }

    private BindingInfo buildFromKid(Object kid) {
        String kidStr = kid.toString();
        String subjectId = kidStr.contains("#") ? kidStr.split("#")[0] : kidStr;
        log.info("Binding from proof: cnfType=kid, subjectId={}", subjectId);
        return new BindingInfo(subjectId, Map.of("kid", kidStr));
    }

    @SuppressWarnings("unchecked")
    private BindingInfo buildFromJwk(Object jwk) throws ProofValidationException {
        if (!(jwk instanceof Map<?, ?> jwkMap)) {
            throw new ProofValidationException("jwk must be a JSON object");
        }
        var jwkObj = (Map<String, Object>) jwkMap;
        String subjectIdFromJwk = UUID.randomUUID().toString();
        log.info("Binding from proof: cnfType=jwk, subjectId={}", subjectIdFromJwk);
        return new BindingInfo(subjectIdFromJwk, Map.of("jwk", jwkObj));
    }

}
