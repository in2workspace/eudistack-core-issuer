package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.oidc4vci.application.workflow.Oid4VciCredentialWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.BindingInfo;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import es.in2.issuer.backend.shared.domain.service.ProofValidationService;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.naming.ConfigurationException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
public class Oid4VciCredentialWorkflowImpl implements Oid4VciCredentialWorkflow {

    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final ProofValidationService proofValidationService;
    private final ProcedureService procedureService;
    private final CredentialIssuerMetadataService credentialIssuerMetadataService;
    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final StatusListWorkflow statusListWorkflow;
    private final CacheStore<String> enrichmentCacheStore;
    private final CacheStore<String> notificationCacheStore;

    public Oid4VciCredentialWorkflowImpl(
            CredentialSignerWorkflow credentialSignerWorkflow,
            ProofValidationService proofValidationService,
            ProcedureService procedureService,
            CredentialIssuerMetadataService credentialIssuerMetadataService,
            GenericCredentialBuilder genericCredentialBuilder,
            CredentialProfileRegistry credentialProfileRegistry,
            StatusListWorkflow statusListWorkflow,
            @Qualifier("enrichmentCacheStore") CacheStore<String> enrichmentCacheStore,
            @Qualifier("notificationCacheStore") CacheStore<String> notificationCacheStore
    ) {
        this.credentialSignerWorkflow = credentialSignerWorkflow;
        this.proofValidationService = proofValidationService;
        this.procedureService = procedureService;
        this.credentialIssuerMetadataService = credentialIssuerMetadataService;
        this.genericCredentialBuilder = genericCredentialBuilder;
        this.credentialProfileRegistry = credentialProfileRegistry;
        this.statusListWorkflow = statusListWorkflow;
        this.enrichmentCacheStore = enrichmentCacheStore;
        this.notificationCacheStore = notificationCacheStore;
    }

    /**
     * OID4VCI credential issuance flow:
     * 1. Load procedure (verify DRAFT status)
     * 2. Validate proof if required → extract BindingInfo (cnf)
     * 3. Enrich credential in memory (bind issuer) — NOT persisted to DB
     * 4. Allocate status list entry (revocation) and inject credentialStatus
     * 5. Cache enriched dataSet for later persistence on credential_accepted
     * 6. Sign credential (builds JWT/SD-JWT payload with cnf, signs)
     * 7. Generate notification_id, cache mapping notificationId → procedureId
     * 8. Return CredentialResponse with signed credential + notification_id
     *
     * Status stays DRAFT until wallet confirms via credential_accepted notification.
     */
    @Override
    @Observed(name = "oid4vci.generate-vc-response", contextualName = "oid4vci-generate-vc-response")
    public Mono<CredentialResponse> createCredentialResponse(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext) {

        final String procedureId = accessTokenContext.procedureId();

        return procedureService.getProcedureById(procedureId)
                .switchIfEmpty(Mono.error(new InvalidTokenException("Procedure not found: " + procedureId)))
                .flatMap(proc -> validateProcedureState(proc)
                        .then(Mono.fromCallable(credentialIssuerMetadataService::getCredentialIssuerMetadata))
                        .flatMap(metadata -> {
                            log.info("[{}] Processing credential request: procedureId={}, type={}, format={}",
                                    processId, procedureId, proc.getCredentialType(), proc.getCredentialFormat());

                            return validateAndDetermineBindingInfo(proc, metadata, credentialRequest)
                                    .defaultIfEmpty(new BindingInfo(null, null))
                                    .flatMap(bindingInfo ->
                                            enrichAndSign(processId, proc, bindingInfo, accessTokenContext.rawToken()));
                        })
                );
    }

    private Mono<Void> validateProcedureState(CredentialProcedure proc) {
        if (proc.getCredentialStatus() != CredentialStatusEnum.DRAFT) {
            return Mono.error(new InvalidCredentialFormatException(
                    "Credential procedure is not in DRAFT status: " + proc.getCredentialStatus()));
        }
        return Mono.empty();
    }

    private Mono<CredentialResponse> enrichAndSign(
            String processId,
            CredentialProcedure proc,
            BindingInfo bindingInfo,
            String rawToken) {

        String procedureId = proc.getProcedureId().toString();
        String credentialType = proc.getCredentialType();
        String email = proc.getEmail();
        String credentialFormat = proc.getCredentialFormat() != null ? proc.getCredentialFormat() : JWT_VC_JSON;

        CredentialProfile profile = credentialProfileRegistry.getByCredentialType(credentialType);
        if (profile == null) {
            return Mono.error(new FormatUnsupportedException("No profile for credential type: " + credentialType));
        }

        Map<String, Object> cnf = bindingInfo.cnf();
        String token = BEARER_PREFIX + rawToken;
        StatusListFormat statusFormat = DC_SD_JWT.equals(credentialFormat)
                ? StatusListFormat.TOKEN_JWT : StatusListFormat.BITSTRING_VC;

        // Step 1: Bind issuer to the credential dataSet (in memory, NOT persisted)
        return genericCredentialBuilder.bindIssuer(profile, proc.getCredentialDataSet(), procedureId, email)
                // Step 2: Allocate status list entry and inject credentialStatus
                .flatMap(enrichedDataSet ->
                        statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, statusFormat, procedureId, token)
                                .map(entry -> {
                                    CredentialStatus status = CredentialStatus.fromStatusListEntry(entry);
                                    return genericCredentialBuilder.injectCredentialStatus(
                                            enrichedDataSet, status, credentialFormat);
                                })
                )
                .flatMap(enrichedWithStatus ->
                        // Step 3: Cache enriched dataSet for later persistence on credential_accepted
                        enrichmentCacheStore.add(procedureId, enrichedWithStatus)
                                // Step 4: Sign using enriched data directly (no DB read)
                                .then(credentialSignerWorkflow.signCredential(
                                        token, enrichedWithStatus, credentialType,
                                        credentialFormat, cnf, procedureId, email))
                )
                .flatMap(signedCredential -> {
                    // Step 5: Generate notification_id and cache mapping
                    String notificationId = UUID.randomUUID().toString();
                    return notificationCacheStore.add(notificationId, procedureId)
                            .thenReturn(CredentialResponse.builder()
                                    .credentials(List.of(CredentialResponse.Credential.builder()
                                            .credential(signedCredential)
                                            .build()))
                                    .notificationId(notificationId)
                                    .build());
                })
                .doOnSuccess(resp -> log.info("[{}] Credential signed successfully for procedureId={}", processId, procedureId));
    }

    // --- Proof validation logic (kept from existing implementation) ---

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

        return proofValidationService.verifyProof(jwtProof, proofSigningAlgs, expectedAudience)
                .flatMap(valid -> {
                    if (!Boolean.TRUE.equals(valid)) {
                        return Mono.error(new InvalidOrMissingProofException("Invalid proof"));
                    }
                    return extractBindingInfoFromJwtProof(jwtProof);
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
