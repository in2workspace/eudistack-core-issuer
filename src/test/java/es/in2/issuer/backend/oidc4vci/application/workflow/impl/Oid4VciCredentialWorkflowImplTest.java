package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialResponse;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import es.in2.issuer.backend.shared.domain.service.ProofValidationService;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class Oid4VciCredentialWorkflowImplTest {

    private CredentialSignerWorkflow credentialSignerWorkflow;
    private ProofValidationService proofValidationService;
    private ProcedureService procedureService;
    private CredentialIssuerMetadataService credentialIssuerMetadataService;
    private GenericCredentialBuilder genericCredentialBuilder;
    private CredentialProfileRegistry credentialProfileRegistry;
    private StatusListWorkflow statusListWorkflow;
    private CacheStore<String> enrichmentCacheStore;
    private CacheStore<String> notificationCacheStore;

    private Oid4VciCredentialWorkflowImpl workflow;

    private static final String PROCESS_ID = "process-123";
    private static final String RAW_TOKEN = "raw-access-token";
    private static final UUID PROCEDURE_UUID = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
    private static final String PROCEDURE_ID = PROCEDURE_UUID.toString();
    private static final String CREDENTIAL_TYPE = "LEARCredentialEmployee";
    private static final String CREDENTIAL_DATA_SET = "{\"type\":[\"VerifiableCredential\",\"LEARCredentialEmployee\"]}";

    @SuppressWarnings("unchecked")
    @BeforeEach
    void setUp() {
        credentialSignerWorkflow = mock(CredentialSignerWorkflow.class);
        proofValidationService = mock(ProofValidationService.class);
        procedureService = mock(ProcedureService.class);
        credentialIssuerMetadataService = mock(CredentialIssuerMetadataService.class);
        genericCredentialBuilder = mock(GenericCredentialBuilder.class);
        credentialProfileRegistry = mock(CredentialProfileRegistry.class);
        statusListWorkflow = mock(StatusListWorkflow.class);
        enrichmentCacheStore = mock(CacheStore.class);
        notificationCacheStore = mock(CacheStore.class);

        workflow = new Oid4VciCredentialWorkflowImpl(
                credentialSignerWorkflow,
                proofValidationService,
                procedureService,
                credentialIssuerMetadataService,
                genericCredentialBuilder,
                credentialProfileRegistry,
                statusListWorkflow,
                enrichmentCacheStore,
                notificationCacheStore
        );
    }

    @Test
    void createCredentialResponse_jwtVcJson_fullFlowWithStatusListAllocation() {
        // Arrange
        CredentialProcedure procedure = buildProcedure(JWT_VC_JSON);
        CredentialProfile profile = buildProfile(false);
        CredentialIssuerMetadata metadata = buildMetadata(null);
        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .procedureId(PROCEDURE_ID)
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

        when(procedureService.getProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(procedure));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata()).thenReturn(metadata);
        when(credentialProfileRegistry.getByCredentialType(CREDENTIAL_TYPE)).thenReturn(profile);
        when(genericCredentialBuilder.bindIssuer(eq(profile), eq(CREDENTIAL_DATA_SET), eq(PROCEDURE_ID), anyString()))
                .thenReturn(Mono.just(enrichedDataSet));
        when(statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC, PROCEDURE_ID, BEARER_PREFIX + RAW_TOKEN))
                .thenReturn(Mono.just(statusEntry));
        when(genericCredentialBuilder.injectCredentialStatus(eq(enrichedDataSet), any(CredentialStatus.class), eq(JWT_VC_JSON)))
                .thenReturn(enrichedWithStatus);
        when(enrichmentCacheStore.add(eq(PROCEDURE_ID), eq(enrichedWithStatus)))
                .thenReturn(Mono.just(enrichedWithStatus));
        when(credentialSignerWorkflow.signCredential(
                eq(BEARER_PREFIX + RAW_TOKEN), eq(enrichedWithStatus), eq(CREDENTIAL_TYPE),
                eq(JWT_VC_JSON), isNull(), eq(PROCEDURE_ID), anyString()))
                .thenReturn(Mono.just(signedCredential));
        when(notificationCacheStore.add(anyString(), eq(PROCEDURE_ID)))
                .thenReturn(Mono.just(PROCEDURE_ID));

        // Act & Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context))
                .assertNext(resp -> {
                    assertThat(resp.credentials()).hasSize(1);
                    assertThat(resp.credentials().getFirst().credential()).isEqualTo(signedCredential);
                    assertThat(resp.notificationId()).isNotBlank();
                })
                .verifyComplete();

        // Verify status list allocation with BITSTRING_VC for jwt_vc_json format
        verify(statusListWorkflow).allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC, PROCEDURE_ID, BEARER_PREFIX + RAW_TOKEN);
        verify(genericCredentialBuilder).injectCredentialStatus(eq(enrichedDataSet), any(CredentialStatus.class), eq(JWT_VC_JSON));
        verify(enrichmentCacheStore).add(eq(PROCEDURE_ID), eq(enrichedWithStatus));
        verify(notificationCacheStore).add(anyString(), eq(PROCEDURE_ID));
    }

    @Test
    void createCredentialResponse_dcSdJwt_usesTokenJwtFormat() {
        // Arrange
        CredentialProcedure procedure = buildProcedure(DC_SD_JWT);
        CredentialProfile profile = buildProfile(false);
        CredentialIssuerMetadata metadata = buildMetadata(null);
        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(DC_SD_JWT)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .procedureId(PROCEDURE_ID)
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

        when(procedureService.getProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(procedure));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata()).thenReturn(metadata);
        when(credentialProfileRegistry.getByCredentialType(CREDENTIAL_TYPE)).thenReturn(profile);
        when(genericCredentialBuilder.bindIssuer(eq(profile), eq(CREDENTIAL_DATA_SET), eq(PROCEDURE_ID), anyString()))
                .thenReturn(Mono.just(enrichedDataSet));
        when(statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.TOKEN_JWT, PROCEDURE_ID, BEARER_PREFIX + RAW_TOKEN))
                .thenReturn(Mono.just(statusEntry));
        when(genericCredentialBuilder.injectCredentialStatus(eq(enrichedDataSet), any(CredentialStatus.class), eq(DC_SD_JWT)))
                .thenReturn(enrichedWithStatus);
        when(enrichmentCacheStore.add(eq(PROCEDURE_ID), eq(enrichedWithStatus)))
                .thenReturn(Mono.just(enrichedWithStatus));
        when(credentialSignerWorkflow.signCredential(
                eq(BEARER_PREFIX + RAW_TOKEN), eq(enrichedWithStatus), eq(CREDENTIAL_TYPE),
                eq(DC_SD_JWT), isNull(), eq(PROCEDURE_ID), anyString()))
                .thenReturn(Mono.just(signedCredential));
        when(notificationCacheStore.add(anyString(), eq(PROCEDURE_ID)))
                .thenReturn(Mono.just(PROCEDURE_ID));

        // Act & Assert
        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context))
                .assertNext(resp -> {
                    assertThat(resp.credentials()).hasSize(1);
                    assertThat(resp.credentials().getFirst().credential()).isEqualTo(signedCredential);
                })
                .verifyComplete();

        // Verify TOKEN_JWT format used for dc+sd-jwt
        verify(statusListWorkflow).allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.TOKEN_JWT, PROCEDURE_ID, BEARER_PREFIX + RAW_TOKEN);
        verify(genericCredentialBuilder).injectCredentialStatus(eq(enrichedDataSet), any(CredentialStatus.class), eq(DC_SD_JWT));
    }

    @Test
    void createCredentialResponse_procedureNotDraft_returnsError() {
        CredentialProcedure procedure = buildProcedure(JWT_VC_JSON);
        procedure.setCredentialStatus(CredentialStatusEnum.ISSUED);

        CredentialIssuerMetadata metadata = buildMetadata(null);

        when(procedureService.getProcedureById(PROCEDURE_ID)).thenReturn(Mono.just(procedure));
        when(credentialIssuerMetadataService.getCredentialIssuerMetadata()).thenReturn(metadata);

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .procedureId(PROCEDURE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context))
                .expectError()
                .verify();
    }

    @Test
    void createCredentialResponse_procedureNotFound_returnsInvalidTokenError() {
        when(procedureService.getProcedureById(PROCEDURE_ID)).thenReturn(Mono.empty());

        CredentialRequest request = CredentialRequest.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .format(JWT_VC_JSON)
                .build();
        AccessTokenContext context = AccessTokenContext.builder()
                .rawToken(RAW_TOKEN)
                .procedureId(PROCEDURE_ID)
                .build();

        StepVerifier.create(workflow.createCredentialResponse(PROCESS_ID, request, context))
                .expectError()
                .verify();
    }

    // ---- Helpers ----

    private CredentialProcedure buildProcedure(String format) {
        return CredentialProcedure.builder()
                .procedureId(PROCEDURE_UUID)
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
}
