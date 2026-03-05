package es.in2.issuer.backend.shared.application.workflow.impl;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.oidc4vci.application.workflow.PreAuthorizedCodeWorkflow;
import es.in2.issuer.backend.shared.application.workflow.CredentialIssuanceWorkflow;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.BindingInfo;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.util.JwtUtils;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.IssuancePdpService;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import javax.naming.ConfigurationException;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.PEND_SIGNATURE;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialIssuanceWorkflowImpl implements CredentialIssuanceWorkflow {

    private final VerifiableCredentialService verifiableCredentialService;
    private final StatusListWorkflow statusListWorkflow;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final IssuerProperties appConfig;
    private final ProofValidationService proofValidationService;
    private final EmailService emailService;
    private final CredentialProcedureService credentialProcedureService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;
    private final IssuancePdpService issuancePdpService;
    private final CredentialIssuerMetadataService credentialIssuerMetadataService;
    private final JwtUtils jwtUtils;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final PreAuthorizedCodeWorkflow preAuthorizedCodeWorkflow;
    private final CredentialOfferService credentialOfferService;
    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final PayloadSchemaValidator payloadSchemaValidator;
    private final IssuanceMetrics issuanceMetrics;

    @Observed(name = "issuance.execute", contextualName = "issuance-execute")
    @Override
    public Mono<IssuanceResponse> execute(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest, String token, String idToken) {
        var sample = issuanceMetrics.startTimer();
        String configId = preSubmittedCredentialDataRequest.credentialConfigurationId();
        String delivery = preSubmittedCredentialDataRequest.delivery() != null ? preSubmittedCredentialDataRequest.delivery() : DELIVERY_EMAIL;

        return validateRequest(preSubmittedCredentialDataRequest, idToken)
                .then(payloadSchemaValidator.validate(configId, preSubmittedCredentialDataRequest.payload()))
                .then(issuancePdpService.authorize(token, configId, preSubmittedCredentialDataRequest.payload(), idToken))
                .then(issueCredential(processId, preSubmittedCredentialDataRequest, token))
                .doOnSuccess(r -> issuanceMetrics.recordSuccess(sample, configId, delivery))
                .doOnError(e -> issuanceMetrics.recordError(sample, configId, delivery));
    }

    @Observed(name = "issuance.execute-bootstrap", contextualName = "issuance-execute-bootstrap")
    @Override
    public Mono<IssuanceResponse> executeWithoutAuthorization(String processId, PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest) {
        return validateRequest(preSubmittedCredentialDataRequest, null)
                .then(payloadSchemaValidator.validate(preSubmittedCredentialDataRequest.credentialConfigurationId(), preSubmittedCredentialDataRequest.payload()))
                .then(issueCredential(processId, preSubmittedCredentialDataRequest, "bootstrap"));
    }

    private Mono<Void> validateRequest(PreSubmittedCredentialDataRequest request, String idToken) {
        if (request.email() == null || request.email().isBlank()) {
            return Mono.error(new IllegalArgumentException("email is required"));
        }
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(request.credentialConfigurationId());
        if (profile == null) {
            return Mono.error(new CredentialTypeUnsupportedException(
                    "Unknown credential_configuration_id: " + request.credentialConfigurationId()));
        }
        if (profile.credentialType().equals(LABEL_CREDENTIAL) && idToken == null) {
            return Mono.error(new MissingIdTokenHeaderException("Missing required ID Token header for VerifiableCertification issuance."));
        }
        return Mono.empty();
    }

    private Mono<IssuanceResponse> issueCredential(String processId, PreSubmittedCredentialDataRequest request, String token) {
        CredentialOfferEmailNotificationInfo emailInfo = extractCredentialOfferEmailInfo(request);
        String procedureId = UUID.randomUUID().toString();
        String credentialType = resolveCredentialType(request.credentialConfigurationId());
        String delivery = request.delivery() != null ? request.delivery() : DELIVERY_EMAIL;

        return statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, procedureId, token)
                .map(this::toCredentialStatus)
                .flatMap(credentialStatus -> verifiableCredentialService.generateVc(processId, request, emailInfo.email(), credentialStatus, procedureId))
                .flatMap(transactionCode -> generateCredentialOffer(transactionCode, procedureId, credentialType, emailInfo, delivery));
    }

    /**
     * Generates the credential offer, caches it, and handles delivery:
     * - immediate: returns the credential_offer_uri (no email)
     * - deferred: sends email with QR + wallet deep link + re-issue link, returns empty response
     */
    private Mono<IssuanceResponse> generateCredentialOffer(
            String transactionCode,
            String procedureId,
            String credentialType,
            CredentialOfferEmailNotificationInfo emailInfo,
            String delivery
    ) {
        return preAuthorizedCodeWorkflow.generatePreAuthorizedCode(Mono.just(procedureId))
                .flatMap(preAuthResponse ->
                        deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(
                                transactionCode, preAuthResponse.grants().preAuthorizedCode()
                        )
                        .then(credentialOfferService.buildCustomCredentialOffer(
                                credentialType, preAuthResponse.grants(), emailInfo.email(), preAuthResponse.pin()
                        ))
                        .flatMap(credentialOfferCacheRepository::saveCustomCredentialOffer)
                        .flatMap(credentialOfferService::createCredentialOfferUriResponse)
                        .flatMap(credentialOfferUri -> {
                            if (DELIVERY_UI.equals(delivery)) {
                                log.info("Credential offer URI (ui): {}", credentialOfferUri);
                                return Mono.just(IssuanceResponse.builder()
                                        .credentialOfferUri(credentialOfferUri)
                                        .build());
                            }
                            // deferred: send email and return empty response
                            String reissueUrl = buildReissueUrl(transactionCode);
                            return emailService.sendCredentialOfferEmail(
                                            emailInfo.email(),
                                            CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                                            credentialOfferUri,
                                            reissueUrl,
                                            appConfig.getWalletFrontendUrl(),
                                            emailInfo.organization()
                                    )
                                    .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                                    .thenReturn(IssuanceResponse.builder().build());
                        })
                );
    }

    private String buildReissueUrl(String transactionCode) {
        return UriComponentsBuilder
                .fromUriString(appConfig.getIssuerBackendUrl())
                .path("/oid4vci/v1/credential-offer/reissue/" + transactionCode)
                .build()
                .toUriString();
    }

    // Get the necessary information to send the credential offer email
    private CredentialOfferEmailNotificationInfo extractCredentialOfferEmailInfo(PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest) {
        String credentialConfigurationId = preSubmittedCredentialDataRequest.credentialConfigurationId();
        var payload = preSubmittedCredentialDataRequest.payload();

        String credentialType = resolveCredentialType(credentialConfigurationId);

        return switch (credentialType) {
            case LEAR_CREDENTIAL_EMPLOYEE -> {
                String email = payload.get(MANDATEE).get(EMAIL).asText();
                String org = payload.get(MANDATOR).get(ORGANIZATION).asText();
                yield new CredentialOfferEmailNotificationInfo(email, org);
            }
            case LEAR_CREDENTIAL_MACHINE -> {
                String email;
                if (preSubmittedCredentialDataRequest.email() == null || preSubmittedCredentialDataRequest.email().isBlank()) {
                    email = payload.get(MANDATOR).get(EMAIL).asText();
                    log.debug("No credential owner email found in presubmitted data. Using mandator email: {}", payload.get(MANDATOR).get(EMAIL).asText());
                } else {
                    email = preSubmittedCredentialDataRequest.email();
                }
                String org = payload.get(MANDATOR).get(ORGANIZATION).asText();
                yield new CredentialOfferEmailNotificationInfo(email, org);
            }
            case LABEL_CREDENTIAL -> {
                if (preSubmittedCredentialDataRequest.email() == null || preSubmittedCredentialDataRequest.email().isBlank()) {
                    throw new MissingEmailOwnerException("Email owner email is required for gx:LabelCredential schema");
                }
                String email = preSubmittedCredentialDataRequest.email();
                yield new CredentialOfferEmailNotificationInfo(email, appConfig.getSysTenant());
            }
            default -> throw new FormatUnsupportedException(
                    "Unknown credential type: " + credentialType + " (from credential_configuration_id: " + credentialConfigurationId + ")"
            );
        };
    }

    private String resolveCredentialType(String credentialConfigurationId) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        if (profile == null) {
            throw new CredentialTypeUnsupportedException(
                    "Unknown credential_configuration_id: " + credentialConfigurationId);
        }
        return profile.credentialType();
    }

    @Observed(name = "issuance.generate-vc-response", contextualName = "issuance-generate-vc-response")
    @Override
    public Mono<CredentialResponse> generateVerifiableCredentialResponse(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext
    ) {

        final String nonce = accessTokenContext.jti();
        final String procedureId = accessTokenContext.procedureId();

        return credentialProcedureService.getCredentialProcedureById(procedureId)
                .zipWhen(proc -> credentialIssuerMetadataService.getCredentialIssuerMetadata(processId))
                .flatMap(tuple -> {
                    CredentialProcedure proc = tuple.getT1();
                    CredentialIssuerMetadata md = tuple.getT2();

                    String email = proc.getEmail();

                    log.info(
                            "[{}] Loaded procedure context: nonce(jti)={}, procedureId={}, credentialType={}",
                            processId,
                            nonce,
                            procedureId,
                            proc.getCredentialType()
                    );

                    Mono<BindingInfo> bindingInfoMono = validateAndDetermineBindingInfo(proc, md, credentialRequest)
                            .doOnNext(bi -> log.info(
                                    "[{}] Binding required -> subjectId={}, cnfKeys={}",
                                    processId,
                                    bi.subjectId(),
                                    (bi.cnf() instanceof java.util.Map<?, ?> m) ? m.keySet() : "unknown"
                            ))
                            .flatMap(bi ->
                                    credentialProcedureService.updateCnf(proc.getProcedureId().toString(), bi.cnf())
                                            .thenReturn(bi)
                            )
                            .doOnSuccess(bi -> {
                                if (bi == null) {
                                    log.info("[{}] No cryptographic binding required for credentialType={}",
                                            processId, proc.getCredentialType());
                                }
                            });

                    Mono<CredentialResponse> vcMono = bindingInfoMono
                            .flatMap(bi -> verifiableCredentialService.buildCredentialResponse(
                                    processId,
                                    bi.subjectId(),
                                    nonce,
                                    email,
                                    procedureId
                            ))
                            .switchIfEmpty(Mono.defer(() -> verifiableCredentialService.buildCredentialResponse(
                                    processId,
                                    null,
                                    nonce,
                                    email,
                                    procedureId
                            )));

                    return vcMono.flatMap(cr ->
                            signAndDeliverCredential(processId, cr, proc, accessTokenContext.rawToken())
                    );
                });
    }

    private Mono<BindingInfo> validateAndDetermineBindingInfo(
            CredentialProcedure credentialProcedure,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest
    ) {

        log.debug("validateAndDetermineBindingInfo: credentialType={}", credentialProcedure.getCredentialType());

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

    private Mono<CredentialIssuerMetadata.CredentialConfiguration> findIssuerConfig(CredentialIssuerMetadata metadata, String configId) {
        return Mono.justOrEmpty(
                        metadata.credentialConfigurationsSupported().get(configId)
                )
                .switchIfEmpty(Mono.error(new FormatUnsupportedException(
                        "No configuration for configId: " + configId
                )));
    }

    private Mono<BindingInfo> evaluateCryptographicBinding(
            CredentialIssuerMetadata.CredentialConfiguration cfg,
            String credentialType,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest
    ) {
        var cryptoMethods = cfg.cryptographicBindingMethodsSupported();

        boolean needsProof = cryptoMethods != null && !cryptoMethods.isEmpty();
        log.info("Binding requirement for {}: needsProof={}", credentialType, needsProof);

        if (!needsProof) {
            return Mono.empty();
        }

        String cryptoBindingMethod = selectCryptoBindingMethod(cryptoMethods, credentialType);
        log.debug("Crypto binding method for {}: {}", credentialType, cryptoBindingMethod);

        Set<String> proofSigningAlgoritms = resolveProofSigningAlgorithms(cfg);
        log.debug("Proof signing algs for {}: {}", credentialType, proofSigningAlgoritms);

        String jwtProof = extractFirstJwtProof(credentialRequest);
        String expectedAudience = metadata.credentialIssuer();

        return validateProofAndExtractBindingInfo(jwtProof, proofSigningAlgoritms, expectedAudience, credentialType);
    }

    private String selectCryptoBindingMethod(Set<String> cryptoMethods, String credentialType) {
        String cryptoBindingMethod;
        try {
            cryptoBindingMethod = cryptoMethods.stream()
                    .findFirst()
                    .orElseThrow(() -> new InvalidCredentialFormatException(
                            "No cryptographic binding method configured for " + credentialType
                    ));
        } catch (InvalidCredentialFormatException e) {
            throw new InvalidCredentialFormatException("No cryptographic binding method configured");
        }
        return cryptoBindingMethod;
    }

    private Set<String> resolveProofSigningAlgorithms(CredentialIssuerMetadata.CredentialConfiguration cfg) {
        var proofTypes = cfg.proofTypesSupported();
        var jwtProofConfig = (proofTypes != null) ? proofTypes.get("jwt") : null;

        return (jwtProofConfig != null) ? jwtProofConfig.proofSigningAlgValuesSupported() : null;
    }

    private String extractFirstJwtProof(CredentialRequest credentialRequest) {
        return credentialRequest.proof() != null
                ? credentialRequest.proof().jwt()
                : null;
    }

    private Mono<BindingInfo> validateProofAndExtractBindingInfo(
            String jwtProof,
            Set<String> proofSigningAlgoritms,
            String expectedAudience,
            String credentialType
    ) {
        if (proofSigningAlgoritms == null || proofSigningAlgoritms.isEmpty()) {
            return Mono.error(new ConfigurationException(
                    "No proof_signing_alg_values_supported configured for proof type 'jwt' " +
                            "and credential type " + credentialType
            ));
        }

        if (jwtProof == null) {
            return Mono.error(new InvalidOrMissingProofException(
                    "Missing proof for type " + credentialType
            ));
        }

        return proofValidationService
                .isProofValid(jwtProof, proofSigningAlgoritms, expectedAudience)
                .doOnNext(valid ->
                        log.info("Proof validation result for {}: {}", credentialType, valid)
                )
                .flatMap(valid -> {
                    if (!Boolean.TRUE.equals(valid)) {
                        return Mono.error(new InvalidOrMissingProofException("Invalid proof"));
                    }
                    return extractBindingInfoFromJwtProof(jwtProof);
                });
    }


    private Mono<CredentialResponse> signAndDeliverCredential(
            String processId,
            CredentialResponse cr,
            CredentialProcedure proc,
            String rawToken
    ) {
        return credentialProcedureService.getCredentialStatusByProcedureId(proc.getProcedureId().toString())
                .flatMap(status -> {
                    Mono<Void> upd = !PEND_SIGNATURE.toString().equals(status)
                            ? credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(proc.getProcedureId().toString())
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
                                    log.warn("[{}] Signing failed ({}), falling back to deferred response", processId, e.getMessage());
                                    return Mono.just(cr);
                                }
                                return Mono.error(e);
                            })
                    );
                });
    }

    @Override
    public Mono<Void> bindAccessTokenByPreAuthorizedCode(String processId, AuthServerNonceRequest authServerNonceRequest) {
        return verifiableCredentialService.bindAccessTokenByPreAuthorizedCode
                (processId, authServerNonceRequest.accessToken(), authServerNonceRequest.preAuthorizedCode());
    }

    @Override
    public Mono<CredentialResponse> generateVerifiableCredentialDeferredResponse(
            String processId,
            DeferredCredentialRequest deferredCredentialRequest,
            AccessTokenContext accessTokenContext) {
        String transactionId = deferredCredentialRequest.transactionId();
        log.debug("ProcessID: {} Generating verifiable credential deferred response for transactionId: {}", processId, transactionId);

        return deferredCredentialMetadataService.getDeferredCredentialMetadataByAuthServerNonce(accessTokenContext.jti())
                .flatMap(deferred ->
                        credentialProcedureService.getCredentialProcedureById(deferred.getProcedureId().toString())
                                .flatMap(procedure ->
                                        verifiableCredentialService.generateDeferredCredentialResponse(procedure, transactionId)));
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

            // 1) kid
            if (kid != null) {
                return buildFromKid(kid);
            }
            // 2) x5c
            else if (x5c != null) {
                return buildFromX5c();
            }
            // 3) jwk
            else if (jwk != null) {
                return buildFromJwk(jwk);
            }

            throw new ProofValidationException("No key material found in proof header");
        });
    }

    private BindingInfo buildFromKid(Object kid) {
        String kidStr = kid.toString();
        String subjectId = kidStr.contains("#") ? kidStr.split("#")[0] : kidStr;

        log.info("Binding extracted from proof: cnfType=kid, subjectId={}, kidPrefix={}",
                subjectId,
                kidStr.length() > 20 ? kidStr.substring(0, 20) : kidStr
        );

        return new BindingInfo(subjectId, java.util.Map.of("kid", kidStr));
    }

    private BindingInfo buildFromX5c() throws ProofValidationException {
        throw new ProofValidationException("x5c not supported yet");
    }

    private CredentialStatus toCredentialStatus(StatusListEntry entry) {
        return CredentialStatus.builder()
                .id(entry.id())
                .type(entry.type())
                .statusPurpose(entry.statusPurpose().value())
                .statusListIndex(String.valueOf(entry.statusListIndex()))
                .statusListCredential(entry.statusListCredential())
                .build();
    }

    private BindingInfo buildFromJwk(Object jwk) throws ProofValidationException {
        if (!(jwk instanceof java.util.Map<?, ?> jwkMap)) {
            throw new ProofValidationException("jwk must be a JSON object");
        }

        var jwkObj = (java.util.Map<String, Object>) jwkMap;
        String subjectIdFromJwk = UUID.randomUUID().toString();

        log.info("Binding extracted from proof: cnfType=jwk, subjectId={}", subjectIdFromJwk);
        return new BindingInfo(subjectIdFromJwk, java.util.Map.of("jwk", jwkObj));
    }


}