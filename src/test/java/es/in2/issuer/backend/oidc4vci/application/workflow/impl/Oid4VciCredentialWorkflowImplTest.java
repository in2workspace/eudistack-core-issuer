package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.CredentialRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.Proofs;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialIdentifierException;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.Proof;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuedLogger;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.ProofValidationService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class Oid4VciCredentialWorkflowImplTest {

    private CredentialSignerWorkflow credentialSignerWorkflow;
    private ProofValidationService proofValidationService;
    private IssuanceService issuanceService;
    private CredentialIssuerMetadataService credentialIssuerMetadataService;
    private GenericCredentialBuilder genericCredentialBuilder;
    private CredentialProfileRegistry credentialProfileRegistry;
    private StatusListWorkflow statusListWorkflow;
    private TransientStore<String> enrichmentCacheStore;
    private TransientStore<String> notificationCacheStore;
    private CredentialIssuedLogger credentialIssuedLogger;

    private Oid4VciCredentialWorkflowImpl workflow;

    private static final String PROCESS_ID = "process-123";
    private static final String RAW_TOKEN = "raw-access-token";
    private static final String PUBLIC_BASE_URL = "https://test.example/issuer";
    private static final UUID ISSUANCE_UUID = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
    private static final String ISSUANCE_ID = ISSUANCE_UUID.toString();
    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.4";
    private static final String CREDENTIAL_DATA_SET = "{\"type\":[\"VerifiableCredential\",\"learcredential.employee.w3c.4\"]}";

    @SuppressWarnings("unchecked")
    @BeforeEach
    void setUp() {
        credentialSignerWorkflow = mock(CredentialSignerWorkflow.class);
        proofValidationService = mock(ProofValidationService.class);
        issuanceService = mock(IssuanceService.class);
        credentialIssuerMetadataService = mock(CredentialIssuerMetadataService.class);
        genericCredentialBuilder = mock(GenericCredentialBuilder.class);
        credentialProfileRegistry = mock(CredentialProfileRegistry.class);
        statusListWorkflow = mock(StatusListWorkflow.class);
        enrichmentCacheStore = mock(TransientStore.class);
        notificationCacheStore = mock(TransientStore.class);
        credentialIssuedLogger = mock(CredentialIssuedLogger.class);

        workflow = new Oid4VciCredentialWorkflowImpl(
                credentialSignerWorkflow,
                proofValidationService,
                issuanceService,
                credentialIssuerMetadataService,
                genericCredentialBuilder,
                credentialProfileRegistry,
                statusListWorkflow,
                enrichmentCacheStore,
                notificationCacheStore,
                credentialIssuedLogger
        );

        // Common mocks to avoid NPE when a test reaches further than expected
        lenient().when(genericCredentialBuilder.bindIssuer(any(), any(), any(), any()))
                .thenReturn(Mono.just("{}"));
        lenient().when(genericCredentialBuilder.bindHolderDid(any(), any()))
                .thenReturn("{}");
        lenient().when(genericCredentialBuilder.injectCredentialStatus(any(), any(), any()))
                .thenReturn("{}");
        lenient().when(enrichmentCacheStore.add(any(), any()))
                .thenReturn(Mono.just("{}"));
        lenient().when(notificationCacheStore.add(any(), any()))
                .thenReturn(Mono.just("id"));
        lenient().when(statusListWorkflow.allocateEntry(any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new StatusListEntry("u", "t", StatusPurpose.REVOCATION, "1", "u")));
        lenient().when(credentialSignerWorkflow.signCredential(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just("signed"));
        lenient().when(issuanceService.updateIssuance(any()))
                .thenReturn(Mono.just(Issuance.builder().build()));
        lenient().when(proofValidationService.verifyProof(any(), any(), any()))
                .thenReturn(Mono.just(false));
    }

    @Test
    void createCredentialResponse_jwtVcJson_fullFlowWithStatusListAllocation() {
        // Arrange
        Issuance issuance = buildProcedure(JWT_VC_JSON);
        CredentialProfile profile = buildProfile(false);
        CredentialIssuerMetadata metadata = buildMetadata(null);
        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StatusListEntry statusEntry = new StatusListEntry(
                "https://issuer.example/status/1#42",
                "BitstringStatusListEntry",
                StatusPurpose.REVOCATION,
                "42",
                "https://issuer.example/status/1"
        );

        String enrichedDataSet = "{\"enriched\":true}";
        String enrichedWithStatus = "{\"enriched\":true,\"credentialStatus\":{}}";
        String signedCredential = "signed-jwt-vc";

        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL)).thenReturn(Mono.just(metadata));
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);
        when(genericCredentialBuilder.bindIssuer(eq(profile), eq(CREDENTIAL_DATA_SET), eq(ISSUANCE_ID), anyString()))
                .thenReturn(Mono.just(enrichedDataSet));
        when(statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC, ISSUANCE_ID, BEARER_PREFIX + RAW_TOKEN, PUBLIC_BASE_URL))
                .thenReturn(Mono.just(statusEntry));
        when(genericCredentialBuilder.injectCredentialStatus(eq(enrichedDataSet), any(CredentialStatus.class), eq(JWT_VC_JSON)))
                .thenReturn(enrichedWithStatus);
        when(enrichmentCacheStore.add(eq(ISSUANCE_ID), eq(enrichedWithStatus)))
                .thenReturn(Mono.just(enrichedWithStatus));
        when(credentialSignerWorkflow.signCredential(
                eq(BEARER_PREFIX + RAW_TOKEN), eq(enrichedWithStatus), eq(CREDENTIAL_TYPE),
                eq(JWT_VC_JSON), isNull(), eq(ISSUANCE_ID), anyString()))
                .thenReturn(Mono.just(signedCredential));
        when(notificationCacheStore.add(anyString(), eq(ISSUANCE_ID)))
                .thenReturn(Mono.just(ISSUANCE_ID));
        when(issuanceService.updateIssuance(any(Issuance.class)))
                .thenReturn(Mono.just(issuance));

        // Act & Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .assertNext(resp -> {
                    assertThat(resp.credentials()).hasSize(1);
                    assertThat(resp.credentials().getFirst().credential()).isEqualTo(signedCredential);
                    assertThat(resp.notificationId()).isNotBlank();
                })
                .verifyComplete();

        // Verify status list allocation with BITSTRING_VC for jwt_vc_json format
        verify(statusListWorkflow).allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC, ISSUANCE_ID, BEARER_PREFIX + RAW_TOKEN, PUBLIC_BASE_URL);
        verify(genericCredentialBuilder).injectCredentialStatus(eq(enrichedDataSet), any(CredentialStatus.class), eq(JWT_VC_JSON));
        verify(enrichmentCacheStore).add(eq(ISSUANCE_ID), eq(enrichedWithStatus));
        verify(notificationCacheStore).add(anyString(), eq(ISSUANCE_ID));

        verify(credentialIssuedLogger).logIssued(CREDENTIAL_TYPE);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void createCredentialResponse_dcSdJwt_usesTokenJwtFormat() {
        // Arrange
        Issuance issuance = buildProcedure(DC_SD_JWT);
        CredentialProfile profile = buildProfile(false);
        CredentialIssuerMetadata metadata = buildMetadata(null);
        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(DC_SD_JWT)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StatusListEntry statusEntry = new StatusListEntry(
                "https://issuer.example/token/status/1#42",
                "TokenStatusListEntry",
                StatusPurpose.REVOCATION,
                "42",
                "https://issuer.example/token/status/1"
        );

        String enrichedDataSet = "{\"enriched\":true}";
        String enrichedWithStatus = "{\"enriched\":true,\"status\":{\"status_list\":{}}}";
        String signedCredential = "signed-sd-jwt~disclosure1~";

        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL)).thenReturn(Mono.just(metadata));
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);
        when(genericCredentialBuilder.bindIssuer(eq(profile), eq(CREDENTIAL_DATA_SET), eq(ISSUANCE_ID), anyString()))
                .thenReturn(Mono.just(enrichedDataSet));
        when(statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.TOKEN_JWT, ISSUANCE_ID, BEARER_PREFIX + RAW_TOKEN, PUBLIC_BASE_URL))
                .thenReturn(Mono.just(statusEntry));
        when(genericCredentialBuilder.injectCredentialStatus(eq(enrichedDataSet), any(CredentialStatus.class), eq(DC_SD_JWT)))
                .thenReturn(enrichedWithStatus);
        when(enrichmentCacheStore.add(eq(ISSUANCE_ID), eq(enrichedWithStatus)))
                .thenReturn(Mono.just(enrichedWithStatus));
        when(credentialSignerWorkflow.signCredential(
                eq(BEARER_PREFIX + RAW_TOKEN), eq(enrichedWithStatus), eq(CREDENTIAL_TYPE),
                eq(DC_SD_JWT), isNull(), eq(ISSUANCE_ID), anyString()))
                .thenReturn(Mono.just(signedCredential));
        when(notificationCacheStore.add(anyString(), eq(ISSUANCE_ID)))
                .thenReturn(Mono.just(ISSUANCE_ID));
        when(issuanceService.updateIssuance(any(Issuance.class)))
                .thenReturn(Mono.just(issuance));

        // Act & Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .assertNext(resp -> {
                    assertThat(resp.credentials()).hasSize(1);
                    assertThat(resp.credentials().getFirst().credential()).isEqualTo(signedCredential);
                })
                .verifyComplete();

        // Verify TOKEN_JWT format used for dc+sd-jwt
        verify(statusListWorkflow).allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.TOKEN_JWT, ISSUANCE_ID, BEARER_PREFIX + RAW_TOKEN, PUBLIC_BASE_URL);
        verify(genericCredentialBuilder).injectCredentialStatus(eq(enrichedDataSet), any(CredentialStatus.class), eq(DC_SD_JWT));

        verify(credentialIssuedLogger).logIssued(CREDENTIAL_TYPE);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void createCredentialResponse_withProofsPlural_extractsJwtFromProofsArray() {
        // OID4VCI 1.0 Final §8.2 "proofs" (plural) form - must resolve the same as the
        // legacy singular "proof" would.
        Issuance issuance = buildProcedure(JWT_VC_JSON);
        CredentialProfile profile = buildProfile(true);
        String expectedIssuer = "https://issuer.example.com";
        CredentialIssuerMetadata.CredentialConfiguration config =
                CredentialIssuerMetadata.CredentialConfiguration.builder()
                        .format(JWT_VC_JSON)
                        .cryptographicBindingMethodsSupported(Set.of("did:key"))
                        .proofTypesSupported(Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                                .proofSigningAlgValuesSupported(Set.of("ES256"))
                                .build()))
                        .build();
        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .credentialIssuer(expectedIssuer)
                .credentialEndpoint(expectedIssuer + "/oid4vci/v1/credential")
                .credentialConfigurationsSupported(Map.of(CREDENTIAL_TYPE, config))
                .build();

        String kid = "did:key:zDnaevN85Z7VJgcBoQeqQU7d8kZpuVhDSdm8hQtJYWjvek3VL#key-1";
        String jwtProof = buildJwtProofWithKid(kid);

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .proofs(Proofs.builder().jwt(java.util.List.of(jwtProof)).build())
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StatusListEntry statusEntry = new StatusListEntry(
                "https://issuer.example/status/1#7",
                "BitstringStatusListEntry",
                StatusPurpose.REVOCATION,
                "7",
                "https://issuer.example/status/1"
        );

        String enrichedDataSet = "{\"enriched\":true}";
        String boundDataSet = "{\"enriched\":true,\"holderBound\":true}";
        String enrichedWithStatus = "{\"enriched\":true,\"credentialStatus\":{}}";
        String signedCredential = "signed-jwt-vc";

        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL)).thenReturn(Mono.just(metadata));
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);
        when(proofValidationService.verifyProof(eq(jwtProof), eq(Set.of("ES256")), eq(expectedIssuer)))
                .thenReturn(Mono.just(true));
        when(genericCredentialBuilder.bindIssuer(eq(profile), eq(CREDENTIAL_DATA_SET), eq(ISSUANCE_ID), anyString()))
                .thenReturn(Mono.just(enrichedDataSet));
        when(genericCredentialBuilder.bindHolderDid(eq(enrichedDataSet), anyString()))
                .thenReturn(boundDataSet);
        when(statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC, ISSUANCE_ID, BEARER_PREFIX + RAW_TOKEN, PUBLIC_BASE_URL))
                .thenReturn(Mono.just(statusEntry));
        when(genericCredentialBuilder.injectCredentialStatus(eq(boundDataSet), any(CredentialStatus.class), eq(JWT_VC_JSON)))
                .thenReturn(enrichedWithStatus);
        when(enrichmentCacheStore.add(eq(ISSUANCE_ID), eq(enrichedWithStatus)))
                .thenReturn(Mono.just(enrichedWithStatus));
        when(credentialSignerWorkflow.signCredential(
                eq(BEARER_PREFIX + RAW_TOKEN), eq(enrichedWithStatus), eq(CREDENTIAL_TYPE),
                eq(JWT_VC_JSON), eq(Map.of("kid", kid)), eq(ISSUANCE_ID), anyString()))
                .thenReturn(Mono.just(signedCredential));
        when(notificationCacheStore.add(anyString(), eq(ISSUANCE_ID)))
                .thenReturn(Mono.just(ISSUANCE_ID));
        when(issuanceService.updateIssuance(any(Issuance.class)))
                .thenReturn(Mono.just(issuance));

        // Act & Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .assertNext(resp -> {
                    assertThat(resp.credentials()).hasSize(1);
                    assertThat(resp.credentials().getFirst().credential()).isEqualTo(signedCredential);
                })
                .verifyComplete();

        verify(proofValidationService).verifyProof(eq(jwtProof), eq(Set.of("ES256")), eq(expectedIssuer));
    }

    @Test
    void createCredentialResponse_procedureNotDraft_returnsError() {
        Issuance issuance = buildProcedure(JWT_VC_JSON);
        issuance.setCredentialStatus(CredentialStatusEnum.ISSUED);

        CredentialIssuerMetadata metadata = buildMetadata(null);

        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL)).thenReturn(Mono.just(metadata));
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(buildProfile(false));

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .expectError()
                .verify();

        // The issuance did load, so the authoritative type (from the Issuance, not the request)
        // is what gets logged on the error.
        verify(credentialIssuedLogger).logFailed(eq(CREDENTIAL_TYPE), any());
        verify(credentialIssuedLogger, never()).logIssued(any());
    }

    @Test
    void createCredentialResponse_procedureNotFound_returnsInvalidTokenError() {
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.empty());
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(buildProfile(false));

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .expectError()
                .verify();

        // The issuance never loaded — the only source of the type is the (registry-validated)
        // requested configuration_id.
        verify(credentialIssuedLogger).logFailed(eq(CREDENTIAL_TYPE), any());
    }

    @Test
    void createCredentialResponse_unknownRequestedType_notFound_tagsConfigurationIdUnknown() {
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.empty());
        when(credentialProfileRegistry.getByConfigurationId("../../evil-unbounded-value")).thenReturn(null);

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId("../../evil-unbounded-value")
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .expectError()
                .verify();

        // Cardinality guard: a client-controlled, non-registered configuration_id must never
        // reach the log field — it falls back to null, which CredentialIssuedLogger renders as "unknown".
        verify(credentialIssuedLogger).logFailed(isNull(), any());
    }

    @Test
    void createCredentialResponse_credentialIdentifierPresent_alwaysRejectsAsUnknown() {
        // This Issuer never returns authorization_details with credential_identifiers from
        // the Token Response - only the scope-based flow is implemented - so any
        // credential_identifier a client sends is unrecognized by construction, regardless of
        // its value or of anything else in the request. Checked before the
        // credential_configuration_id guards and before touching the Issuance at all.
        CredentialRequest request = CredentialRequest.builder()
                .credentialIdentifier("some-opaque-identifier")
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .expectError(UnknownCredentialIdentifierException.class)
                .verify();

        verifyNoInteractions(issuanceService);
        verifyNoInteractions(credentialProfileRegistry);
        verify(credentialIssuedLogger).logFailed(isNull(), any());
    }

    @Test
    void createCredentialResponse_unknownRequestedConfigurationId_rejectsBeforeIssuanceLookup() {
        // Distinct from the test above: here the session/Issuance is perfectly valid and would
        // otherwise happily issue - the only problem is credential_configuration_id in the
        // request itself. Regression test for the OID4VCI-1FINAL-fail-unknown-credential-configuration
        // conformance gap: the Issuer used to ignore this field entirely and issue whatever type
        // the Issuance record already had.
        when(credentialProfileRegistry.getByConfigurationId("does-not-exist")).thenReturn(null);

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId("does-not-exist")
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .expectError(UnknownCredentialConfigurationException.class)
                .verify();

        verifyNoInteractions(issuanceService);
        verify(credentialIssuedLogger).logFailed(isNull(), any());
    }

    @Test
    void createCredentialResponse_knownButMismatchedConfigurationId_rejectsAfterIssuanceLookup() {
        // Distinct from both tests above: "eu.europa.ec.eudi.pid.1" IS a real, registered
        // configuration - just not the one this Issuance/token was authorized for, which is
        // CREDENTIAL_TYPE, a LEAR Employee credential set up by the buildProcedure helper.
        // A well-behaved wallet never triggers this: the credential offer service always
        // advertises exactly the Issuance's own credential type in the offer, so this only
        // fires for a request asking for something other than what was actually offered.
        String mismatchedConfigId = "eu.europa.ec.eudi.pid.1";
        Issuance issuance = buildProcedure(JWT_VC_JSON);

        when(credentialProfileRegistry.getByConfigurationId(mismatchedConfigId)).thenReturn(buildProfile(false));
        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(mismatchedConfigId)
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .expectError(UnknownCredentialConfigurationException.class)
                .verify();

        // The Issuance did load, so the authoritative type (from the Issuance, not the
        // mismatched request) is what gets logged.
        verify(credentialIssuedLogger).logFailed(eq(CREDENTIAL_TYPE), any());
    }

    @Test
    void createCredentialResponse_noRequestedConfigurationId_fallsBackToIssuanceType() {
        // credential_configuration_id is nullable - the request could instead be using
        // credential_identifier (covered separately) - confirms both new guards, unknown-config
        // and mismatched-config, correctly no-op when it's absent, falling through to the
        // pre-existing Issuance-type-driven behavior.
        Issuance issuance = buildProcedure(JWT_VC_JSON);
        CredentialProfile profile = buildProfile(false);
        CredentialIssuerMetadata metadata = buildMetadata(null);

        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL)).thenReturn(Mono.just(metadata));
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);

        CredentialRequest request = CredentialRequest.builder()
                .format(JWT_VC_JSON)
                .build(); // credentialConfigurationId left unset (null)
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .assertNext(resp -> assertThat(resp.credentials()).isNotEmpty())
                .verifyComplete();

        verify(credentialIssuedLogger).logIssued(CREDENTIAL_TYPE);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void createCredentialResponse_blankRequestedConfigurationId_fallsBackToIssuanceType() {
        // Same as above but a distinct code path: an empty string is non-null yet still
        // blank - a separate bytecode branch from the null case in both new guards.
        Issuance issuance = buildProcedure(JWT_VC_JSON);
        CredentialProfile profile = buildProfile(false);
        CredentialIssuerMetadata metadata = buildMetadata(null);

        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL)).thenReturn(Mono.just(metadata));
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId("")
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .assertNext(resp -> assertThat(resp.credentials()).isNotEmpty())
                .verifyComplete();

        verify(credentialIssuedLogger).logIssued(CREDENTIAL_TYPE);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void createCredentialResponse_withJwkProof_shouldResolveBinding() throws Exception {
        Issuance issuance = buildProcedure(JWT_VC_JSON);
        CredentialProfile profile = buildProfile(true);
        String expectedIssuer = "https://issuer.example.com";
        CredentialIssuerMetadata.CredentialConfiguration config =
                CredentialIssuerMetadata.CredentialConfiguration.builder()
                        .format(JWT_VC_JSON)
                        .cryptographicBindingMethodsSupported(Set.of("jwk"))
                        .proofTypesSupported(Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                                .proofSigningAlgValuesSupported(Set.of("ES256"))
                                .build()))
                        .build();
        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .credentialIssuer(expectedIssuer)
                .credentialEndpoint(expectedIssuer + "/oid4vci/v1/credential")
                .credentialConfigurationsSupported(Map.of(CREDENTIAL_TYPE, config))
                .build();

        ECKey ecJwk = new ECKeyGenerator(Curve.P_256).keyID("test-kid").generate();
        Map<String, Object> jwk = ecJwk.toPublicJWK().toJSONObject();
        String jwtProof = buildJwtProofWithJwk(jwk);

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .proof(Proof.builder().jwt(jwtProof).build())
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .issuanceId(ISSUANCE_ID)
                .build();

        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL)).thenReturn(Mono.just(metadata));
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);
        when(proofValidationService.verifyProof(eq(jwtProof), eq(Set.of("ES256")), eq(expectedIssuer)))
                .thenReturn(Mono.just(true));

        when(statusListWorkflow.allocateEntry(any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new StatusListEntry("u", "t", StatusPurpose.REVOCATION, "1", "u")));
        when(credentialSignerWorkflow.signCredential(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just("signed"));
        when(issuanceService.updateIssuance(any())).thenReturn(Mono.just(issuance));

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .assertNext(resp -> assertThat(resp.credentials()).isNotEmpty())
                .verifyComplete();
    }

    @Test
    void createCredentialResponse_profileNotFoundInEnrich_shouldError() {
        Issuance issuance = buildProcedure(JWT_VC_JSON);
        CredentialIssuerMetadata metadata = buildMetadata(null);

        when(issuanceService.getIssuanceById(ISSUANCE_ID)).thenReturn(Mono.just(issuance));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata(PUBLIC_BASE_URL)).thenReturn(Mono.just(metadata));

        // credential_configuration_id is known when the request arrives (1st call, the
        // createCredentialResponse-level guard) but the profile has since been removed from the
        // registry by the time enrichAndSign looks it up again (2nd call) - simulates the gap
        // this test targets, distinct from an unknown-at-request-time configuration_id.
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE))
                .thenReturn(buildProfile(false))
                .thenReturn(null);

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .build();
        AccessTokenContext context = AccessTokenContext.builder().issuanceId(ISSUANCE_ID).rawToken(RAW_TOKEN).build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context, PUBLIC_BASE_URL))
                .expectError(FormatUnsupportedException.class)
                .verify();
    }

    // ---- Helpers ----

    private Issuance buildProcedure(String format) {
        return Issuance.builder()
                .issuanceId(ISSUANCE_UUID)
                .credentialFormat(format)
                .credentialType(CREDENTIAL_TYPE)
                .credentialDataSet(CREDENTIAL_DATA_SET)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .email("user@example.com")
                .build();
    }

    private CredentialProfile buildProfile(boolean cnfRequired) {
        return CredentialProfile.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(JWT_VC_JSON)
                .cnfRequired(cnfRequired)
                .issuerType(CredentialProfile.IssuerType.SIMPLE)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(java.util.List.of("VerifiableCredential", CREDENTIAL_TYPE))
                        .build())
                .build();
    }

    private CredentialIssuerMetadata buildMetadata(Set<String> bindingMethods) {
        CredentialIssuerMetadata.CredentialConfiguration config =
                CredentialIssuerMetadata.CredentialConfiguration.builder()
                        .format(JWT_VC_JSON)
                        .cryptographicBindingMethodsSupported(bindingMethods)
                        .build();

        return CredentialIssuerMetadata.builder()
                .credentialIssuer("https://issuer.example.com")
                .credentialEndpoint("https://issuer.example.com/oid4vci/v1/credential")
                .credentialConfigurationsSupported(Map.of(CREDENTIAL_TYPE, config))
                .build();
    }

    // Minimal syntactically-valid JWS compact serialization (header.payload.signature) with
    // a "kid" header claim. proofValidationService (mocked) owns signature verification, so
    // the signature segment content is irrelevant here - only extractBindingInfoFromJwtProof's
    // header parsing is exercised.
    private String buildJwtProofWithKid(String kid) {
        var encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString(
                ("{\"kid\":\"" + kid + "\",\"alg\":\"ES256\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String payload = encoder.encodeToString("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }

    private String buildJwtProofWithJwk(Map<String, Object> jwk) {
        var encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        try {
            String header = encoder.encodeToString(
                    new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(
                            Map.of("jwk", jwk, "alg", "ES256")
                    ));
            String payload = encoder.encodeToString("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return header + "." + payload + ".sig";
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
