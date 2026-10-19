package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.CredentialRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.Proofs;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.InvalidOrMissingProofException;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.Proof;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuedLogger;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.domain.service.HolderDidFallbackAuditor;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.ProofValidationService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.naming.ConfigurationException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static es.in2.issuer.backend.shared.domain.util.Constants.DC_SD_JWT;
import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers the alternative and negative branches of {@link Oid4VciCredentialWorkflowImpl} not reached by
 * {@link Oid4VciCredentialWorkflowImplTest}: null requests, missing issuance type, proof configuration
 * and proof header edge cases, non-DID kid binding and stale stored format.
 */
@ExtendWith(MockitoExtension.class)
class Oid4VciCredentialWorkflowImplBranchesTest {

    private static final String PROCESS_ID = "process-1";
    private static final String PUBLIC_BASE_URL = "https://issuer.example.com";
    private static final UUID ISSUANCE_UUID = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
    private static final String ISSUANCE_ID = ISSUANCE_UUID.toString();
    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.4";
    private static final AccessTokenContext TOKEN = new AccessTokenContext("raw", "jti", ISSUANCE_ID, null);

    @Mock
    private CredentialSignerWorkflow credentialSignerWorkflow;
    @Mock
    private ProofValidationService proofValidationService;
    @Mock
    private IssuanceService issuanceService;
    @Mock
    private CredentialIssuerMetadataService credentialIssuerMetadataService;
    @Mock
    private GenericCredentialBuilder genericCredentialBuilder;
    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;
    @Mock
    private StatusListWorkflow statusListWorkflow;
    @Mock
    private TransientStore<String> enrichmentCacheStore;
    @Mock
    private TransientStore<String> notificationCacheStore;
    @Mock
    private CredentialIssuedLogger credentialIssuedLogger;
    @Mock
    private AuditService auditService;

    private Oid4VciCredentialWorkflowImpl workflow;

    @BeforeEach
    void setUp() {
        workflow = new Oid4VciCredentialWorkflowImpl(
                credentialSignerWorkflow, proofValidationService, issuanceService,
                credentialIssuerMetadataService, genericCredentialBuilder, credentialProfileRegistry,
                statusListWorkflow, enrichmentCacheStore, notificationCacheStore, credentialIssuedLogger,
                new HolderDidFallbackAuditor(auditService), auditService);
        lenient().when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL))
                .thenReturn(Mono.just(metadataWithProofTypes(Map.of("jwt",
                        CredentialProfile.ProofTypeConfig.builder()
                                .proofSigningAlgValuesSupported(Set.of("ES256")).build()))));
    }

    // --- issuance type resolution ---

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void createCredentialResponse_withoutRequestAndIssuanceType_failsMissingCredentialType(String storedType) {
        // Arrange
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance(storedType, JWT_VC_JSON)));

        // Act + Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, null, TOKEN, PUBLIC_BASE_URL))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(FormatUnsupportedException.class)
                        .hasMessageContaining("Missing credential type in issuance"))
                .verify();
        verify(credentialIssuedLogger).logFailed(isNull(), any());
    }

    @Test
    void createCredentialResponse_knownRequestedIdButIssuanceWithoutType_isNotTreatedAsMismatch() {
        // Arrange
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile(JWT_VC_JSON));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance(null, JWT_VC_JSON)));
        CredentialRequest request = new CredentialRequest(CREDENTIAL_TYPE, null, null, null, null);

        // Act + Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, TOKEN, PUBLIC_BASE_URL))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(FormatUnsupportedException.class)
                        .hasMessageContaining("Missing credential type in issuance"))
                .verify();
        verify(credentialIssuedLogger).logFailed(eq(CREDENTIAL_TYPE), any());
    }

    // --- proof configuration ---

    static Stream<Arguments> proofTypesWithoutJwtAlgs() {
        return Stream.of(
                Arguments.of(Named.of("no jwt proof type", Map.of("ldp_vp",
                        CredentialProfile.ProofTypeConfig.builder().proofSigningAlgValuesSupported(Set.of("ES256")).build()))),
                Arguments.of(Named.of("jwt proof type without algs", Map.of("jwt",
                        CredentialProfile.ProofTypeConfig.builder().build()))),
                Arguments.of(Named.of("jwt proof type with empty algs", Map.of("jwt",
                        CredentialProfile.ProofTypeConfig.builder().proofSigningAlgValuesSupported(Set.of()).build()))));
    }

    @ParameterizedTest
    @MethodSource("proofTypesWithoutJwtAlgs")
    void createCredentialResponse_whenNoProofSigningAlgs_failsConfiguration(
            Map<String, CredentialProfile.ProofTypeConfig> proofTypes) {
        // Arrange
        when(issuanceService.getIssuanceById(ISSUANCE_ID))
                .thenReturn(Mono.just(issuance(CREDENTIAL_TYPE, JWT_VC_JSON)));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL))
                .thenReturn(Mono.just(metadataWithProofTypes(proofTypes)));

        // Act + Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, requestWithProof(proofWithKid("did:key:z1")),
                        TOKEN, PUBLIC_BASE_URL))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ConfigurationException.class)
                        .hasMessageContaining(CREDENTIAL_TYPE))
                .verify();
    }

    static Stream<Arguments> requestsWithoutProof() {
        return Stream.of(
                Arguments.of(Named.of("no proof nor proofs", new CredentialRequest(null, null, null, null, null))),
                Arguments.of(Named.of("proofs with null jwt", new CredentialRequest(null, null, null, null, new Proofs(null)))),
                Arguments.of(Named.of("proofs with empty jwt", new CredentialRequest(null, null, null, null, new Proofs(List.of())))));
    }

    @ParameterizedTest
    @MethodSource("requestsWithoutProof")
    void createCredentialResponse_whenProofRequiredButMissing_failsMissingProof(CredentialRequest request) {
        // Arrange
        when(issuanceService.getIssuanceById(ISSUANCE_ID))
                .thenReturn(Mono.just(issuance(CREDENTIAL_TYPE, JWT_VC_JSON)));

        // Act + Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, TOKEN, PUBLIC_BASE_URL))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(InvalidOrMissingProofException.class)
                        .hasMessageContaining("Missing proof for type"))
                .verify();
    }

    @Test
    void createCredentialResponse_whenProofInvalid_failsInvalidProof() {
        // Arrange
        String proof = proofWithKid("did:key:z1");
        when(issuanceService.getIssuanceById(ISSUANCE_ID))
                .thenReturn(Mono.just(issuance(CREDENTIAL_TYPE, JWT_VC_JSON)));
        when(proofValidationService.verifyProof(eq(proof), any(), eq(PUBLIC_BASE_URL))).thenReturn(Mono.just(false));

        // Act + Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, requestWithProof(proof), TOKEN, PUBLIC_BASE_URL))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(InvalidOrMissingProofException.class)
                        .hasMessage("Invalid proof"))
                .verify();
    }

    // --- proof header key material ---

    static Stream<Arguments> invalidProofHeaders() {
        return Stream.of(
                Arguments.of(Named.of("no key material", "{\"alg\":\"ES256\"}"),
                        "Expected exactly one of kid/jwk/x5c in proof header"),
                Arguments.of(Named.of("kid and x5c", "{\"alg\":\"ES256\",\"kid\":\"k\",\"x5c\":[\"MIIB\"]}"),
                        "Expected exactly one of kid/jwk/x5c in proof header"),
                Arguments.of(Named.of("x5c only", "{\"alg\":\"ES256\",\"x5c\":[\"MIIB\"]}"),
                        "x5c not supported yet"));
    }

    @ParameterizedTest
    @MethodSource("invalidProofHeaders")
    void createCredentialResponse_whenProofHeaderKeyMaterialInvalid_fails(String headerJson, String expectedMessage) {
        // Arrange
        String proof = rawJwt(headerJson);
        when(issuanceService.getIssuanceById(ISSUANCE_ID))
                .thenReturn(Mono.just(issuance(CREDENTIAL_TYPE, JWT_VC_JSON)));
        when(proofValidationService.verifyProof(eq(proof), any(), any())).thenReturn(Mono.just(true));

        // Act + Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, requestWithProof(proof), TOKEN, PUBLIC_BASE_URL))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ProofValidationException.class)
                        .hasMessage(expectedMessage))
                .verify();
    }

    // --- enrich and sign ---

    @Test
    void createCredentialResponse_withNonDidKidAndStaleStoredFormat_signsWithProfileFormatAndNoHolderDid() {
        // Arrange
        String proof = proofWithKid("key-1");
        Issuance issuance = issuance(CREDENTIAL_TYPE, JWT_VC_JSON);
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));
        when(proofValidationService.verifyProof(eq(proof), any(), any())).thenReturn(Mono.just(true));
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile(DC_SD_JWT));
        when(genericCredentialBuilder.bindIssuer(any(), any(), any(), any())).thenReturn(Mono.just("{}"));
        when(statusListWorkflow.allocateEntry(any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new StatusListEntry("u", "t", StatusPurpose.REVOCATION, "1", "u")));
        when(genericCredentialBuilder.injectCredentialStatus(any(), any(), eq(DC_SD_JWT))).thenReturn("{\"status\":{}}");
        when(enrichmentCacheStore.add(any(), any())).thenReturn(Mono.just("{}"));
        when(credentialSignerWorkflow.signCredential(anyString(), anyString(), eq(CREDENTIAL_TYPE), eq(DC_SD_JWT),
                eq(Map.of("kid", "key-1")), eq(ISSUANCE_ID), any())).thenReturn(Mono.just("signed"));
        when(notificationCacheStore.add(any(), eq(ISSUANCE_ID))).thenReturn(Mono.just(ISSUANCE_ID));
        when(issuanceService.updateIssuance(any())).thenReturn(Mono.just(issuance));

        // Act + Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, requestWithProof(proof), TOKEN, PUBLIC_BASE_URL))
                .assertNext(response -> assertThat(response.credentials()).hasSize(1))
                .verifyComplete();
        verify(genericCredentialBuilder, never()).bindHolderDid(any(), any());
        verify(credentialIssuedLogger).logIssued(CREDENTIAL_TYPE);
    }

    // --- helpers ---

    private static Issuance issuance(String credentialType, String format) {
        return Issuance.builder()
                .issuanceId(ISSUANCE_UUID)
                .credentialType(credentialType)
                .credentialFormat(format)
                .credentialDataSet("{}")
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .email("user@example.com")
                .build();
    }

    private static CredentialProfile profile(String format) {
        return CredentialProfile.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(format)
                .issuerType(CredentialProfile.IssuerType.SIMPLE)
                .build();
    }

    private static CredentialIssuerMetadata metadataWithProofTypes(
            Map<String, CredentialProfile.ProofTypeConfig> proofTypes) {
        CredentialIssuerMetadata.CredentialConfiguration config =
                CredentialIssuerMetadata.CredentialConfiguration.builder()
                        .format(JWT_VC_JSON)
                        .proofTypesSupported(proofTypes)
                        .build();
        return CredentialIssuerMetadata.builder()
                .credentialIssuer(PUBLIC_BASE_URL)
                .credentialConfigurationsSupported(Map.of(CREDENTIAL_TYPE, config))
                .build();
    }

    private static CredentialRequest requestWithProof(String jwt) {
        return new CredentialRequest(null, null, null, new Proof("jwt", jwt), null);
    }

    private static String proofWithKid(String kid) {
        return rawJwt("{\"alg\":\"ES256\",\"kid\":\"" + kid + "\"}");
    }

    private static String rawJwt(String headerJson) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString("{}".getBytes(StandardCharsets.UTF_8)) + ".sig";
    }
}
