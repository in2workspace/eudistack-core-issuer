package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.MissingCredentialTypeException;
import es.in2.issuer.backend.shared.domain.exception.NoCredentialFoundException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.*;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuanceServiceImplTest {

    // Single source of truth for admin org id in tests
    private static final String ADMIN_ORG_ID = "IN2_ADMIN_ORG_ID_FOR_TEST";

    @Mock
    private IssuanceRepository issuanceRepository;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private R2dbcEntityTemplate r2dbcEntityTemplate;

    @Mock
    private IssuerProperties appConfig;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @InjectMocks
    private IssuanceServiceImpl issuanceService;

    @BeforeEach
    void setUp() {
        // Make this stub lenient because some tests exercise regular-org paths only
        org.mockito.Mockito.lenient()
                .when(appConfig.getAdminOrganizationId())
                .thenReturn(ADMIN_ORG_ID);
    }

    @Test
    void saveIssuance_shouldPersistAndReturnIssuance() {
        // Given
        String credentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\"]}}";
        String organizationIdentifier = "org-123";
        UUID issuanceId = UUID.randomUUID();

        Issuance issuance = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialDataSet(credentialDataSet)
                .credentialFormat("jwt_vc_json")
                .organizationIdentifier(organizationIdentifier)
                .credentialType("learcredential.employee.w3c.4")
                .subject("TestSubject")
                .validUntil(new Timestamp(Instant.now().toEpochMilli() + 1000))
                .email("test@example.com")
                .delivery("email")
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .build();

        when(r2dbcEntityTemplate.insert(any(Issuance.class)))
                .thenReturn(Mono.just(issuance));

        // When
        Mono<Issuance> result = issuanceService.saveIssuance(issuance);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(saved ->
                        saved.getIssuanceId().equals(issuanceId) &&
                                saved.getCredentialStatus() == CredentialStatusEnum.DRAFT &&
                                saved.getCredentialDataSet().equals(credentialDataSet) &&
                                saved.getOrganizationIdentifier().equals(organizationIdentifier))
                .verifyComplete();

        verify(r2dbcEntityTemplate, times(1)).insert(any(Issuance.class));
    }

    @Test
    void getCredentialTypeByIssuanceId_shouldReturnNonDefaultType() throws Exception {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String credentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\", \"TestType\"]}}";

        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.fromString(issuanceId));
        issuance.setCredentialDataSet(credentialDataSet);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(issuanceRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(issuance));
        when(objectMapper.readTree(credentialDataSet))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = issuanceService.getCredentialTypeByIssuanceId(issuanceId);

        // Then
        StepVerifier.create(result)
                .expectNext("TestType")
                .verifyComplete();
    }

    @Test
    void getCredentialTypeByIssuanceId_shouldReturnEmptyIfOnlyDefaultTypesPresent() throws Exception {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String credentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\", \"VerifiableAttestation\"]}}";

        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.fromString(issuanceId));
        issuance.setCredentialDataSet(credentialDataSet);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(issuanceRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(issuance));
        when(objectMapper.readTree(credentialDataSet))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = issuanceService.getCredentialTypeByIssuanceId(issuanceId);

        // Then
        StepVerifier.create(result)
                .expectNextCount(0)
                .verifyComplete();
    }

    @Test
    void getCredentialTypeByIssuanceId_shouldReturnErrorIfTypeMissing() throws Exception {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String credentialDataSet = "{\"vc\":{}}";

        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.fromString(issuanceId));
        issuance.setCredentialDataSet(credentialDataSet);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(issuanceRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(issuance));
        when(objectMapper.readTree(credentialDataSet))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = issuanceService.getCredentialTypeByIssuanceId(issuanceId);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(throwable -> throwable instanceof MissingCredentialTypeException &&
                        throwable.getMessage().equals("The credential type is missing"))
                .verify();
    }

    @Test
    void getCredentialTypeByIssuanceId_shouldReturnErrorIfJsonProcessingExceptionOccurs() throws Exception {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String invalidCredentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\", \"TestType\"}";

        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.fromString(issuanceId));
        issuance.setCredentialDataSet(invalidCredentialDataSet);

        when(issuanceRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(issuance));
        when(objectMapper.readTree(invalidCredentialDataSet))
                .thenThrow(new RuntimeException("Invalid JSON"));

        // When
        Mono<String> result = issuanceService.getCredentialTypeByIssuanceId(issuanceId);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(RuntimeException.class::isInstance)
                .verify();
    }

    @Test
    void updateCredentialDataSetByIssuanceId_shouldUpdateAndSaveIssuance() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String newCredential = "{\"vc\":{\"type\":[\"NewCredentialType\"]}}";
        String newFormat = "json";

        Issuance existingIssuance = new Issuance();
        existingIssuance.setIssuanceId(UUID.fromString(issuanceId));
        existingIssuance.setCredentialDataSet("{\"vc\":{\"type\":[\"OldCredentialType\"]}}");
        existingIssuance.setCredentialStatus(CredentialStatusEnum.DRAFT);
        existingIssuance.setCredentialFormat("old_format");

        when(issuanceRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(existingIssuance));
        when(issuanceRepository.save(any(Issuance.class)))
                .thenReturn(Mono.just(existingIssuance));

        // When
        Mono<Void> result = issuanceService.updateCredentialDataSetByIssuanceId(issuanceId, newCredential, newFormat);

        // Then
        StepVerifier.create(result).verifyComplete();

        verify(issuanceRepository, times(1)).findById(UUID.fromString(issuanceId));
        verify(issuanceRepository, times(1)).save(existingIssuance);

        assertEquals(newCredential, existingIssuance.getCredentialDataSet());
        assertEquals(newFormat, existingIssuance.getCredentialFormat());
        assertEquals(CredentialStatusEnum.ISSUED, existingIssuance.getCredentialStatus());
    }

    @Test
    void updateCredentialDataSetByIssuanceId_shouldHandleProcedureNotFound() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String newCredential = "{\"vc\":{\"type\":[\"NewCredentialType\"]}}";
        String newFormat = "json";

        when(issuanceRepository.findById(any(UUID.class)))
                .thenReturn(Mono.empty());

        // When
        Mono<Void> result = issuanceService.updateCredentialDataSetByIssuanceId(issuanceId, newCredential, newFormat);

        // Then
        StepVerifier.create(result).verifyComplete();

        verify(issuanceRepository, times(1)).findById(UUID.fromString(issuanceId));
        verify(issuanceRepository, times(0)).save(any(Issuance.class));
    }

    @Test
    void getCredentialDataSetByIssuanceId_shouldReturnCredentialDataSet() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String expectedCredentialDataSet = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";

        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.fromString(issuanceId));
        issuance.setCredentialDataSet(expectedCredentialDataSet);

        when(issuanceRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(issuance));

        // When
        Mono<String> result = issuanceService.getCredentialDataSetByIssuanceId(issuanceId);

        // Then
        StepVerifier.create(result)
                .expectNext(expectedCredentialDataSet)
                .verifyComplete();
    }

    @Test
    void getCredentialStatusByIssuanceId_shouldReturnCredentialStatus() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        CredentialStatusEnum expectedStatus = CredentialStatusEnum.ISSUED;

        when(issuanceRepository.findCredentialStatusByIssuanceId(any(UUID.class)))
                .thenReturn(Mono.just(expectedStatus.name()));

        // When
        Mono<String> result = issuanceService.getCredentialStatusByIssuanceId(issuanceId);

        // Then
        StepVerifier.create(result)
                .expectNext(expectedStatus.name())
                .verifyComplete();
    }

    @Test
    void getAllIssuedCredentialByOrganizationIdentifier_shouldReturnAllIssuedCredentials() {
        // Given
        String organizationIdentifier = "org-123";
        String credential1DataSet = "{\"vc\":{\"type\":[\"TestCredentialType1\"]}}";
        String credential2DataSet = "{\"vc\":{\"type\":[\"TestCredentialType2\"]}}";

        Issuance issuance1 = new Issuance();
        issuance1.setCredentialDataSet(credential1DataSet);
        issuance1.setCredentialStatus(CredentialStatusEnum.ISSUED);
        issuance1.setOrganizationIdentifier(organizationIdentifier);

        Issuance issuance2 = new Issuance();
        issuance2.setCredentialDataSet(credential2DataSet);
        issuance2.setCredentialStatus(CredentialStatusEnum.ISSUED);
        issuance2.setOrganizationIdentifier(organizationIdentifier);

        when(issuanceRepository.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, organizationIdentifier))
                .thenReturn(Flux.fromIterable(List.of(issuance1, issuance2)));

        // When / Then
        StepVerifier.create(issuanceService.getAllIssuedCredentialByOrganizationIdentifier(organizationIdentifier))
                .expectNext(credential1DataSet)
                .expectNext(credential2DataSet)
                .verifyComplete();
    }

    @Test
    void getAllIssuedCredentialByOrganizationIdentifier_shouldHandleNoIssuedCredentialsFound() {
        // Given
        String organizationIdentifier = "org-456";

        when(issuanceRepository.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, organizationIdentifier))
                .thenReturn(Flux.empty());

        // When / Then
        StepVerifier.create(issuanceService.getAllIssuedCredentialByOrganizationIdentifier(organizationIdentifier))
                .expectNextCount(0)
                .verifyComplete();
    }

    // ---------- Admin bypass tests use boolean sysAdmin parameter ----------

    @Test
    void getIssuanceDetailByIssuanceIdAndOrganizationId_shouldReturnCredentialDetails_forRegularOrg() throws Exception {
        // Given (non-admin path)
        String issuanceId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";
        String credentialDataSet = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";
        UUID expectedProcedureId = UUID.fromString(issuanceId);
        CredentialStatusEnum status = CredentialStatusEnum.ISSUED;
        String email = "owner@example.com";

        Issuance issuance = new Issuance();
        issuance.setIssuanceId(expectedProcedureId);
        issuance.setCredentialDataSet(credentialDataSet);
        issuance.setCredentialStatus(status);
        issuance.setOrganizationIdentifier(organizationIdentifier);
        issuance.setEmail(email);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(issuanceRepository.findByIssuanceIdAndOrganizationIdentifier(any(UUID.class), any(String.class)))
                .thenReturn(Mono.just(issuance));
        when(objectMapper.readTree(credentialDataSet)).thenReturn(credentialNode);

        // When
        Mono<CredentialDetails> result = issuanceService
                .getIssuanceDetailByIssuanceIdAndOrganizationId(organizationIdentifier, issuanceId, false);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(details ->
                        details.issuanceId().equals(expectedProcedureId) &&
                                details.lifeCycleStatus().equals(status.name()) &&
                                details.credential().equals(credentialNode) &&
                                email.equals(details.email())
                )
                .verifyComplete();

        verify(issuanceRepository, times(1))
                .findByIssuanceIdAndOrganizationIdentifier(UUID.fromString(issuanceId), organizationIdentifier);
        verify(issuanceRepository, never()).findByIssuanceId(any(UUID.class));
    }

    @Test
    void getIssuanceDetailByIssuanceIdAndOrganizationId_shouldReturnCredentialDetails_forAdminOrg() throws Exception {
        // Given (admin organization -> bypass via sysAdmin=true)
        String issuanceId = UUID.randomUUID().toString();
        String organizationIdentifier = ADMIN_ORG_ID;
        String credentialDataSet = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";
        UUID expectedProcedureId = UUID.fromString(issuanceId);
        String email = "admin-owner@example.com";

        Issuance issuance = new Issuance();
        issuance.setIssuanceId(expectedProcedureId);
        issuance.setCredentialDataSet(credentialDataSet);
        issuance.setCredentialStatus(CredentialStatusEnum.VALID);
        issuance.setOrganizationIdentifier("any-org");
        issuance.setEmail(email);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(issuanceRepository.findByIssuanceId(any(UUID.class)))
                .thenReturn(Mono.just(issuance));
        when(objectMapper.readTree(credentialDataSet)).thenReturn(credentialNode);

        // When
        Mono<CredentialDetails> result = issuanceService
                .getIssuanceDetailByIssuanceIdAndOrganizationId(organizationIdentifier, issuanceId, true);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(details ->
                        details.issuanceId().equals(expectedProcedureId) &&
                                details.credential().equals(credentialNode) &&
                                email.equals(details.email())
                )
                .verifyComplete();

        verify(issuanceRepository, times(1)).findByIssuanceId(UUID.fromString(issuanceId));
        verify(issuanceRepository, never())
                .findByIssuanceIdAndOrganizationIdentifier(any(UUID.class), anyString());
    }

    @Test
    void getIssuanceDetailByIssuanceIdAndOrganizationId_shouldErrorWhenNotFound_forRegularOrg() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";

        when(issuanceRepository.findByIssuanceIdAndOrganizationIdentifier(any(UUID.class), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<CredentialDetails> result = issuanceService
                .getIssuanceDetailByIssuanceIdAndOrganizationId(organizationIdentifier, issuanceId, false);

        // Then
        StepVerifier.create(result)
                .expectErrorSatisfies(err -> {
                    assertInstanceOf(NoCredentialFoundException.class, err);
                    assertTrue(err.getMessage().contains(issuanceId));
                })
                .verify();
    }

    @Test
    void getIssuanceDetailByIssuanceIdAndOrganizationId_shouldErrorWhenNotFound_forAdminOrg() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String organizationIdentifier = ADMIN_ORG_ID;

        when(issuanceRepository.findByIssuanceId(any(UUID.class)))
                .thenReturn(Mono.empty());

        // When
        Mono<CredentialDetails> result = issuanceService
                .getIssuanceDetailByIssuanceIdAndOrganizationId(organizationIdentifier, issuanceId, true);

        // Then
        StepVerifier.create(result)
                .expectError(NoCredentialFoundException.class)
                .verify();
    }

    @Test
    void getIssuanceDetailByIssuanceIdAndOrganizationId_shouldHandleJsonProcessingException() throws Exception {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";
        String invalidCredentialDataSet = "{\"vc\":{\"type\":[\"TestCredentialType\"}";

        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.fromString(issuanceId));
        issuance.setCredentialDataSet(invalidCredentialDataSet);
        issuance.setOrganizationIdentifier(organizationIdentifier);

        when(issuanceRepository.findByIssuanceIdAndOrganizationIdentifier(any(UUID.class), any(String.class)))
                .thenReturn(Mono.just(issuance));
        when(objectMapper.readTree(invalidCredentialDataSet))
                .thenThrow(new JsonParseException(null, "Error parsing credential"));

        // When
        Mono<CredentialDetails> result = issuanceService
                .getIssuanceDetailByIssuanceIdAndOrganizationId(organizationIdentifier, issuanceId, false);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(JsonParseException.class::isInstance)
                .verify();
    }

    @Test
    void extractCredentialNode_shouldReturnJsonNode_whenInputIsValid() throws Exception {
        // Given
        String credentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\",\"Employee\"]}}";
        Issuance cp = new Issuance();
        cp.setCredentialDataSet(credentialDataSet);

        JsonNode expectedNode = new ObjectMapper().readTree(credentialDataSet);
        when(objectMapper.readTree(credentialDataSet)).thenReturn(expectedNode);

        // When
        Mono<JsonNode> result = issuanceService.extractCredentialNode(cp);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(node ->
                        node.has("vc") && node.equals(expectedNode))
                .verifyComplete();

        verify(objectMapper, times(1)).readTree(credentialDataSet);
    }

    @Test
    void extractCredentialNode_shouldError_whenIssuanceIsNull() {
        // When
        Mono<JsonNode> result = issuanceService.extractCredentialNode(null);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ParseCredentialJsonException &&
                                err.getMessage().equals("Issuance or credentialDataSet is null"))
                .verify();
    }

    @Test
    void extractCredentialNode_shouldError_whenCredentialDataSetIsNull() {
        Issuance cp = new Issuance();
        cp.setCredentialDataSet(null);

        // When
        Mono<JsonNode> result = issuanceService.extractCredentialNode(cp);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ParseCredentialJsonException &&
                                err.getMessage().equals("Issuance or credentialDataSet is null"))
                .verify();
    }

    @Test
    void extractCredentialNode_shouldError_whenJsonIsInvalid() throws Exception {
        String invalidJson = "{\"vc\":{\"type\":[\"VerifiableCredential\",\"Employee\"}";
        Issuance cp = new Issuance();
        cp.setCredentialDataSet(invalidJson);

        doThrow(new JsonParseException(null, "Malformed JSON"))
                .when(objectMapper).readTree(invalidJson);

        // When
        Mono<JsonNode> result = issuanceService.extractCredentialNode(cp);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ParseCredentialJsonException &&
                                err.getMessage().equals("Error parsing credential JSON"))
                .verify();

        verify(objectMapper, times(1)).readTree(invalidJson);
    }

    @Test
    void getAllIssuancesVisibleFor_admin_shouldReturnAllProceduresMapped() {
        // Given (admin organization)
        String adminOrg = ADMIN_ORG_ID;

        Issuance cp1 = new Issuance();
        cp1.setIssuanceId(UUID.randomUUID());
        cp1.setSubject("Alice");
        cp1.setCredentialType("TYPE_A");
        cp1.setCredentialStatus(CredentialStatusEnum.DRAFT);
        cp1.setOrganizationIdentifier("org-1");
        cp1.setUpdatedAt(Instant.parse("2025-01-10T10:00:00Z"));
        cp1.setCredentialDataSet("{\"vc\":{}}");

        Issuance cp2 = new Issuance();
        cp2.setIssuanceId(UUID.randomUUID());
        cp2.setSubject("Bob");
        cp2.setCredentialType("TYPE_B");
        cp2.setCredentialStatus(CredentialStatusEnum.ISSUED);
        cp2.setOrganizationIdentifier("org-2");
        cp2.setUpdatedAt(Instant.parse("2025-02-12T09:30:00Z"));
        cp2.setCredentialDataSet("{\"vc\":{}}");

        when(issuanceRepository.findAllOrderByUpdatedDesc())
                .thenReturn(Flux.fromIterable(List.of(cp2, cp1)));

        // objectMapper.readTree is called inside toIssuanceSummary
        try {
            when(objectMapper.readTree("{\"vc\":{}}")).thenReturn(new ObjectMapper().readTree("{\"vc\":{}}"));
        } catch (Exception ignored) {
        }

        // When
        Mono<IssuanceList> mono = issuanceService.getAllIssuancesVisibleFor(adminOrg, true);

        // Then
        StepVerifier.create(mono)
                .assertNext(result -> {
                    List<IssuanceList.IssuanceEntry> list = result.issuances();
                    assertNotNull(list);
                    assertEquals(2, list.size(), "Should contain 2 procedures");

                    IssuanceSummary first = list.get(0).issuance();
                    IssuanceSummary second = list.get(1).issuance();

                    assertEquals(cp2.getIssuanceId(), first.issuanceId());
                    assertEquals("Bob", first.subject());
                    assertEquals("TYPE_B", first.credentialType());
                    assertEquals(CredentialStatusEnum.ISSUED.name(), first.status());
                    assertEquals("org-2", first.organizationIdentifier());
                    assertEquals(cp2.getUpdatedAt(), first.updated());

                    assertEquals(cp1.getIssuanceId(), second.issuanceId());
                    assertEquals("Alice", second.subject());
                    assertEquals("TYPE_A", second.credentialType());
                    assertEquals(CredentialStatusEnum.DRAFT.name(), second.status());
                    assertEquals("org-1", second.organizationIdentifier());
                    assertEquals(cp1.getUpdatedAt(), second.updated());
                })
                .verifyComplete();

        verify(issuanceRepository, times(1)).findAllOrderByUpdatedDesc();
    }

    @Test
    void getAllIssuancesVisibleFor_regularOrg_shouldDelegateToOrgSpecificMethod() {
        // Given (regular organization)
        String orgId = "org-123";

        Issuance cp = new Issuance();
        cp.setIssuanceId(UUID.randomUUID());
        cp.setSubject("Carol");
        cp.setCredentialType("TYPE_C");
        cp.setCredentialStatus(CredentialStatusEnum.VALID);
        cp.setOrganizationIdentifier(orgId);
        cp.setUpdatedAt(Instant.parse("2025-03-01T08:00:00Z"));

        IssuanceSummary pbi = IssuanceSummary.builder()
                .issuanceId(cp.getIssuanceId())
                .subject(cp.getSubject())
                .credentialType(cp.getCredentialType())
                .status(cp.getCredentialStatus().name())
                .organizationIdentifier(cp.getOrganizationIdentifier())
                .updated(cp.getUpdatedAt())
                .build();

        IssuanceList expected = new IssuanceList(
                List.of(IssuanceList.IssuanceEntry.builder()
                        .issuance(pbi)
                        .build())
        );

        IssuanceServiceImpl spyService = spy(issuanceService);

        doReturn(Mono.just(expected))
                .when(spyService).getAllIssuanceSummariesByOrganizationId(orgId);

        // When
        Mono<IssuanceList> mono = spyService.getAllIssuancesVisibleFor(orgId, false);

        // Then
        StepVerifier.create(mono)
                .expectNextMatches(result ->
                        result.issuances().size() == 1
                                && result.issuances().get(0).issuance().issuanceId().equals(cp.getIssuanceId())
                                && "Carol".equals(result.issuances().get(0).issuance().subject())
                                && "TYPE_C".equals(result.issuances().get(0).issuance().credentialType())
                                && "VALID".equals(result.issuances().get(0).issuance().status())
                                && orgId.equals(result.issuances().get(0).issuance().organizationIdentifier())
                )
                .verifyComplete();

        verify(issuanceRepository, never()).findAllOrderByUpdatedDesc();
        verify(spyService, times(1)).getAllIssuanceSummariesByOrganizationId(orgId);
    }

    @Test
    void getAllProceduresBasicInfoForAllOrganizations_shouldReturnEmptyList_whenRepositoryIsEmpty() {
        // Given
        when(issuanceRepository.findAllOrderByUpdatedDesc())
                .thenReturn(Flux.empty());

        // When
        Mono<IssuanceList> mono = issuanceService.getAllIssuancesVisibleFor(ADMIN_ORG_ID, true);

        // Then
        StepVerifier.create(mono)
                .assertNext(result -> {
                    List<IssuanceList.IssuanceEntry> list = result.issuances();
                    assertNotNull(list);
                    assertTrue(list.isEmpty(), "List should be empty");
                })
                .verifyComplete();

        verify(issuanceRepository, times(1)).findAllOrderByUpdatedDesc();
    }

    @Test
    void getAllIssuanceSummariesByOrganizationId_shouldReturnMappedList_forOrg() {
        // Given
        String orgId = "org-xyz";

        Issuance cp1 = new Issuance();
        cp1.setIssuanceId(UUID.randomUUID());
        cp1.setSubject("Alice");
        cp1.setCredentialType("TYPE_A");
        cp1.setCredentialStatus(CredentialStatusEnum.DRAFT);
        cp1.setOrganizationIdentifier(orgId);
        cp1.setUpdatedAt(Instant.parse("2025-01-10T10:00:00Z"));
        cp1.setCredentialDataSet("{\"vc\":{}}");

        Issuance cp2 = new Issuance();
        cp2.setIssuanceId(UUID.randomUUID());
        cp2.setSubject("Bob");
        cp2.setCredentialType("TYPE_B");
        cp2.setCredentialStatus(CredentialStatusEnum.ISSUED);
        cp2.setOrganizationIdentifier(orgId);
        cp2.setUpdatedAt(Instant.parse("2025-02-12T09:30:00Z"));
        cp2.setCredentialDataSet("{\"vc\":{}}");

        when(issuanceRepository.findAllByOrganizationIdentifier(orgId))
                .thenReturn(Flux.fromIterable(List.of(cp1, cp2)));

        // objectMapper.readTree is called inside toIssuanceSummary
        try {
            when(objectMapper.readTree("{\"vc\":{}}")).thenReturn(new ObjectMapper().readTree("{\"vc\":{}}"));
        } catch (Exception ignored) {
        }

        // When
        Mono<IssuanceList> mono = issuanceService.getAllIssuanceSummariesByOrganizationId(orgId);

        // Then
        StepVerifier.create(mono)
                .assertNext(result -> {
                    List<IssuanceList.IssuanceEntry> list = result.issuances();
                    assertNotNull(list, "Result list should not be null");
                    assertEquals(2, list.size(), "Should contain 2 procedures");

                    IssuanceSummary first = list.get(0).issuance();
                    IssuanceSummary second = list.get(1).issuance();

                    assertEquals(cp1.getIssuanceId(), first.issuanceId());
                    assertEquals("Alice", first.subject());
                    assertEquals("TYPE_A", first.credentialType());
                    assertEquals(CredentialStatusEnum.DRAFT.name(), first.status());
                    assertEquals(orgId, first.organizationIdentifier());
                    assertEquals(cp1.getUpdatedAt(), first.updated());

                    assertEquals(cp2.getIssuanceId(), second.issuanceId());
                    assertEquals("Bob", second.subject());
                    assertEquals("TYPE_B", second.credentialType());
                    assertEquals(CredentialStatusEnum.ISSUED.name(), second.status());
                    assertEquals(orgId, second.organizationIdentifier());
                    assertEquals(cp2.getUpdatedAt(), second.updated());
                })
                .verifyComplete();

        verify(issuanceRepository, times(1)).findAllByOrganizationIdentifier(orgId);
    }

    @Test
    void getAllIssuanceSummariesByOrganizationId_shouldReturnEmptyList_whenRepositoryIsEmpty() {
        // Given
        String orgId = "org-empty";
        when(issuanceRepository.findAllByOrganizationIdentifier(orgId))
                .thenReturn(Flux.empty());

        // When
        Mono<IssuanceList> mono = issuanceService.getAllIssuanceSummariesByOrganizationId(orgId);

        // Then
        StepVerifier.create(mono)
                .assertNext(result -> {
                    List<IssuanceList.IssuanceEntry> list = result.issuances();
                    assertNotNull(list, "Result list should not be null");
                    assertTrue(list.isEmpty(), "List should be empty");
                })
                .verifyComplete();

        verify(issuanceRepository, times(1)).findAllByOrganizationIdentifier(orgId);
    }

    @Test
    void findCredentialOfferEmailInfoByIssuanceId_label_usesSysTenantForOrganization() {
        // given
        String issuanceId = UUID.randomUUID().toString();
        String email = "label.owner@in2.es";
        String sysTenant = "my-sys-tenant-from-config";

        Issuance cp = new Issuance();
        cp.setIssuanceId(UUID.fromString(issuanceId));
        cp.setCredentialType("gx.labelcredential.w3c.1");
        cp.setEmail(email);
        // For LABEL, decoded JSON is not used, so it can be null
        cp.setCredentialDataSet(null);

        CredentialProfile labelProfile = CredentialProfile.builder()
                .credentialConfigurationId("gx.labelcredential.w3c.1")
                .format("jwt_vc_json")
                .organizationExtraction(null)
                .build();
        when(credentialProfileRegistry.getByConfigurationId("gx.labelcredential.w3c.1"))
                .thenReturn(labelProfile);
        when(issuanceRepository.findByIssuanceId(UUID.fromString(issuanceId)))
                .thenReturn(Mono.just(cp));
        when(appConfig.getSysTenant()).thenReturn(sysTenant);

        // when
        Mono<CredentialOfferEmailNotificationInfo> mono =
                issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId);

        // then
        StepVerifier.create(mono)
                .expectNextMatches(info ->
                        email.equals(info.email()) &&
                                sysTenant.equals(info.organization()))
                .verifyComplete();

        verify(issuanceRepository, times(1))
                .findByIssuanceId(UUID.fromString(issuanceId));
        verify(appConfig, times(1)).getSysTenant();
    }

}
