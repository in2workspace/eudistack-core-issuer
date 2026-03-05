package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.MissingCredentialTypeException;
import es.in2.issuer.backend.shared.domain.exception.NoCredentialFoundException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
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
class CredentialProcedureServiceImplTest {

    // Single source of truth for admin org id in tests
    private static final String ADMIN_ORG_ID = "IN2_ADMIN_ORG_ID_FOR_TEST";

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private R2dbcEntityTemplate r2dbcEntityTemplate;

    @Mock
    private IssuerProperties appConfig;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @InjectMocks
    private CredentialProcedureServiceImpl credentialProcedureService;

    @BeforeEach
    void setUp() {
        // Make this stub lenient because some tests exercise regular-org paths only
        org.mockito.Mockito.lenient()
                .when(appConfig.getAdminOrganizationId())
                .thenReturn(ADMIN_ORG_ID);
    }

    @Test
    void createCredentialProcedure_shouldSaveProcedureAndReturnCredentialProcedure() {
        // Given
        String credentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\"]}}";
        String organizationIdentifier = "org-123";
        String expectedProcedureId = UUID.randomUUID().toString();
        String expectedCredentialType = LEAR_CREDENTIAL_EMPLOYEE;
        String expectedSubject = "TestSubject";
        String expectedEmail = "test@example.com";
        Timestamp expectedValidUntil = new Timestamp(Instant.now().toEpochMilli() + 1000);

        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .procedureId(expectedProcedureId)
                .organizationIdentifier(organizationIdentifier)
                .credentialDataSet(credentialDataSet)
                .subject(expectedSubject)
                .credentialType(LEAR_CREDENTIAL_EMPLOYEE)
                .credentialFormat("jwt_vc_json")
                .validUntil(expectedValidUntil)
                .email(expectedEmail)
                .delivery("push")
                .build();

        CredentialProcedure savedCredentialProcedure = CredentialProcedure.builder()
                .procedureId(UUID.fromString(expectedProcedureId))
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialDataSet(credentialDataSet)
                .organizationIdentifier(organizationIdentifier)
                .credentialType(expectedCredentialType)
                .subject(expectedSubject)
                .validUntil(expectedValidUntil)
                .email(expectedEmail)
                .delivery("push")
                .notificationId(UUID.randomUUID())
                .build();

        // Mock
        when(r2dbcEntityTemplate.insert(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(savedCredentialProcedure));

        // When
        Mono<CredentialProcedure> result = credentialProcedureService.createCredentialProcedure(request);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(cp ->
                        cp.getProcedureId().equals(UUID.fromString(expectedProcedureId)) &&
                                cp.getCredentialStatus() == CredentialStatusEnum.DRAFT &&
                                cp.getCredentialDataSet().equals(credentialDataSet) &&
                                cp.getOrganizationIdentifier().equals(organizationIdentifier))
                .verifyComplete();

        verify(r2dbcEntityTemplate, times(1)).insert(any(CredentialProcedure.class));
    }

    @Test
    void getCredentialTypeByProcedureId_shouldReturnNonDefaultType() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String credentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\", \"TestType\"]}}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDataSet(credentialDataSet);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDataSet))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = credentialProcedureService.getCredentialTypeByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectNext("TestType")
                .verifyComplete();
    }

    @Test
    void getCredentialTypeByProcedureId_shouldReturnEmptyIfOnlyDefaultTypesPresent() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String credentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\", \"VerifiableAttestation\"]}}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDataSet(credentialDataSet);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDataSet))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = credentialProcedureService.getCredentialTypeByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectNextCount(0)
                .verifyComplete();
    }

    @Test
    void getCredentialTypeByProcedureId_shouldReturnErrorIfTypeMissing() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String credentialDataSet = "{\"vc\":{}}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDataSet(credentialDataSet);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDataSet))
                .thenReturn(credentialNode);

        // When
        Mono<String> result = credentialProcedureService.getCredentialTypeByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(throwable -> throwable instanceof MissingCredentialTypeException &&
                        throwable.getMessage().equals("The credential type is missing"))
                .verify();
    }

    @Test
    void getCredentialTypeByProcedureId_shouldReturnErrorIfJsonProcessingExceptionOccurs() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String invalidCredentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\", \"TestType\"}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDataSet(invalidCredentialDataSet);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(invalidCredentialDataSet))
                .thenThrow(new RuntimeException("Invalid JSON"));

        // When
        Mono<String> result = credentialProcedureService.getCredentialTypeByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(RuntimeException.class::isInstance)
                .verify();
    }

    @Test
    void updateCredentialDataSetByProcedureId_shouldUpdateAndSaveCredentialProcedure() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String newCredential = "{\"vc\":{\"type\":[\"NewCredentialType\"]}}";
        String newFormat = "json";

        CredentialProcedure existingCredentialProcedure = new CredentialProcedure();
        existingCredentialProcedure.setProcedureId(UUID.fromString(procedureId));
        existingCredentialProcedure.setCredentialDataSet("{\"vc\":{\"type\":[\"OldCredentialType\"]}}");
        existingCredentialProcedure.setCredentialStatus(CredentialStatusEnum.DRAFT);
        existingCredentialProcedure.setCredentialFormat("old_format");

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(existingCredentialProcedure));

        // When
        Mono<Void> result = credentialProcedureService.updateCredentialDataSetByProcedureId(procedureId, newCredential, newFormat);

        // Then
        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureRepository, times(1)).findById(UUID.fromString(procedureId));
        verify(credentialProcedureRepository, times(1)).save(existingCredentialProcedure);

        assertEquals(newCredential, existingCredentialProcedure.getCredentialDataSet());
        assertEquals(newFormat, existingCredentialProcedure.getCredentialFormat());
        assertEquals(CredentialStatusEnum.ISSUED, existingCredentialProcedure.getCredentialStatus());
    }

    @Test
    void updateCredentialDataSetByProcedureId_shouldHandleProcedureNotFound() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String newCredential = "{\"vc\":{\"type\":[\"NewCredentialType\"]}}";
        String newFormat = "json";

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.empty());

        // When
        Mono<Void> result = credentialProcedureService.updateCredentialDataSetByProcedureId(procedureId, newCredential, newFormat);

        // Then
        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureRepository, times(1)).findById(UUID.fromString(procedureId));
        verify(credentialProcedureRepository, times(0)).save(any(CredentialProcedure.class));
    }

    @Test
    void getCredentialDataSetByProcedureId_shouldReturnCredentialDataSet() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String expectedCredentialDataSet = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDataSet(expectedCredentialDataSet);

        when(credentialProcedureRepository.findById(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));

        // When
        Mono<String> result = credentialProcedureService.getCredentialDataSetByProcedureId(procedureId);

        // Then
        StepVerifier.create(result)
                .expectNext(expectedCredentialDataSet)
                .verifyComplete();
    }

    @Test
    void getCredentialStatusByProcedureId_shouldReturnCredentialStatus() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        CredentialStatusEnum expectedStatus = CredentialStatusEnum.ISSUED;

        when(credentialProcedureRepository.findCredentialStatusByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(expectedStatus.name()));

        // When
        Mono<String> result = credentialProcedureService.getCredentialStatusByProcedureId(procedureId);

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

        CredentialProcedure credentialProcedure1 = new CredentialProcedure();
        credentialProcedure1.setCredentialDataSet(credential1DataSet);
        credentialProcedure1.setCredentialStatus(CredentialStatusEnum.ISSUED);
        credentialProcedure1.setOrganizationIdentifier(organizationIdentifier);

        CredentialProcedure credentialProcedure2 = new CredentialProcedure();
        credentialProcedure2.setCredentialDataSet(credential2DataSet);
        credentialProcedure2.setCredentialStatus(CredentialStatusEnum.ISSUED);
        credentialProcedure2.setOrganizationIdentifier(organizationIdentifier);

        when(credentialProcedureRepository.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, organizationIdentifier))
                .thenReturn(Flux.fromIterable(List.of(credentialProcedure1, credentialProcedure2)));

        // When / Then
        StepVerifier.create(credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationIdentifier))
                .expectNext(credential1DataSet)
                .expectNext(credential2DataSet)
                .verifyComplete();
    }

    @Test
    void getAllIssuedCredentialByOrganizationIdentifier_shouldHandleNoIssuedCredentialsFound() {
        // Given
        String organizationIdentifier = "org-456";

        when(credentialProcedureRepository.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, organizationIdentifier))
                .thenReturn(Flux.empty());

        // When / Then
        StepVerifier.create(credentialProcedureService.getAllIssuedCredentialByOrganizationIdentifier(organizationIdentifier))
                .expectNextCount(0)
                .verifyComplete();
    }

    // ---------- Admin bypass tests use boolean sysAdmin parameter ----------

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldReturnCredentialDetails_forRegularOrg() throws Exception {
        // Given (non-admin path)
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";
        String credentialDataSet = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";
        UUID expectedProcedureId = UUID.fromString(procedureId);
        CredentialStatusEnum status = CredentialStatusEnum.ISSUED;
        String email = "owner@example.com";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(expectedProcedureId);
        credentialProcedure.setCredentialDataSet(credentialDataSet);
        credentialProcedure.setCredentialStatus(status);
        credentialProcedure.setOrganizationIdentifier(organizationIdentifier);
        credentialProcedure.setEmail(email);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(any(UUID.class), any(String.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDataSet)).thenReturn(credentialNode);

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId, false);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(details ->
                        details.procedureId().equals(expectedProcedureId) &&
                                details.lifeCycleStatus().equals(status.name()) &&
                                details.credential().equals(credentialNode) &&
                                email.equals(details.email())
                )
                .verifyComplete();

        verify(credentialProcedureRepository, times(1))
                .findByProcedureIdAndOrganizationIdentifier(UUID.fromString(procedureId), organizationIdentifier);
        verify(credentialProcedureRepository, never()).findByProcedureId(any(UUID.class));
    }

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldReturnCredentialDetails_forAdminOrg() throws Exception {
        // Given (admin organization -> bypass via sysAdmin=true)
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = ADMIN_ORG_ID;
        String credentialDataSet = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";
        UUID expectedProcedureId = UUID.fromString(procedureId);
        String email = "admin-owner@example.com";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(expectedProcedureId);
        credentialProcedure.setCredentialDataSet(credentialDataSet);
        credentialProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
        credentialProcedure.setOrganizationIdentifier("any-org");
        credentialProcedure.setEmail(email);

        JsonNode credentialNode = new ObjectMapper().readTree(credentialDataSet);

        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(credentialDataSet)).thenReturn(credentialNode);

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId, true);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(details ->
                        details.procedureId().equals(expectedProcedureId) &&
                                details.credential().equals(credentialNode) &&
                                email.equals(details.email())
                )
                .verifyComplete();

        verify(credentialProcedureRepository, times(1)).findByProcedureId(UUID.fromString(procedureId));
        verify(credentialProcedureRepository, never())
                .findByProcedureIdAndOrganizationIdentifier(any(UUID.class), anyString());
    }

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldErrorWhenNotFound_forRegularOrg() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";

        when(credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(any(UUID.class), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId, false);

        // Then
        StepVerifier.create(result)
                .expectErrorSatisfies(err -> {
                    assertInstanceOf(NoCredentialFoundException.class, err);
                    assertTrue(err.getMessage().contains(procedureId));
                })
                .verify();
    }

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldErrorWhenNotFound_forAdminOrg() {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = ADMIN_ORG_ID;

        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.empty());

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId, true);

        // Then
        StepVerifier.create(result)
                .expectError(NoCredentialFoundException.class)
                .verify();
    }

    @Test
    void getProcedureDetailByProcedureIdAndOrganizationId_shouldHandleJsonProcessingException() throws Exception {
        // Given
        String procedureId = UUID.randomUUID().toString();
        String organizationIdentifier = "org-123";
        String invalidCredentialDataSet = "{\"vc\":{\"type\":[\"TestCredentialType\"}";

        CredentialProcedure credentialProcedure = new CredentialProcedure();
        credentialProcedure.setProcedureId(UUID.fromString(procedureId));
        credentialProcedure.setCredentialDataSet(invalidCredentialDataSet);
        credentialProcedure.setOrganizationIdentifier(organizationIdentifier);

        when(credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(any(UUID.class), any(String.class)))
                .thenReturn(Mono.just(credentialProcedure));
        when(objectMapper.readTree(invalidCredentialDataSet))
                .thenThrow(new JsonParseException(null, "Error parsing credential"));

        // When
        Mono<CredentialDetails> result = credentialProcedureService
                .getProcedureDetailByProcedureIdAndOrganizationId(organizationIdentifier, procedureId, false);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(JsonParseException.class::isInstance)
                .verify();
    }

    @Test
    void getCredentialNode_shouldReturnJsonNode_whenInputIsValid() throws Exception {
        // Given
        String credentialDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\",\"Employee\"]}}";
        CredentialProcedure cp = new CredentialProcedure();
        cp.setCredentialDataSet(credentialDataSet);

        JsonNode expectedNode = new ObjectMapper().readTree(credentialDataSet);
        when(objectMapper.readTree(credentialDataSet)).thenReturn(expectedNode);

        // When
        Mono<JsonNode> result = credentialProcedureService.getCredentialNode(cp);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(node ->
                        node.has("vc") && node.equals(expectedNode))
                .verifyComplete();

        verify(objectMapper, times(1)).readTree(credentialDataSet);
    }

    @Test
    void getCredentialNode_shouldError_whenCredentialProcedureIsNull() {
        // When
        Mono<JsonNode> result = credentialProcedureService.getCredentialNode(null);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ParseCredentialJsonException &&
                                err.getMessage().equals("CredentialProcedure or credentialDataSet is null"))
                .verify();
    }

    @Test
    void getCredentialNode_shouldError_whenCredentialDataSetIsNull() {
        CredentialProcedure cp = new CredentialProcedure();
        cp.setCredentialDataSet(null);

        // When
        Mono<JsonNode> result = credentialProcedureService.getCredentialNode(cp);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ParseCredentialJsonException &&
                                err.getMessage().equals("CredentialProcedure or credentialDataSet is null"))
                .verify();
    }

    @Test
    void getCredentialNode_shouldError_whenJsonIsInvalid() throws Exception {
        String invalidJson = "{\"vc\":{\"type\":[\"VerifiableCredential\",\"Employee\"}";
        CredentialProcedure cp = new CredentialProcedure();
        cp.setCredentialDataSet(invalidJson);

        doThrow(new JsonParseException(null, "Malformed JSON"))
                .when(objectMapper).readTree(invalidJson);

        // When
        Mono<JsonNode> result = credentialProcedureService.getCredentialNode(cp);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(err ->
                        err instanceof ParseCredentialJsonException &&
                                err.getMessage().equals("Error parsing credential JSON"))
                .verify();

        verify(objectMapper, times(1)).readTree(invalidJson);
    }

    @Test
    void getAllProceduresVisibleFor_admin_shouldReturnAllProceduresMapped() {
        // Given (admin organization)
        String adminOrg = ADMIN_ORG_ID;

        CredentialProcedure cp1 = new CredentialProcedure();
        cp1.setProcedureId(UUID.randomUUID());
        cp1.setSubject("Alice");
        cp1.setCredentialType("TYPE_A");
        cp1.setCredentialStatus(CredentialStatusEnum.DRAFT);
        cp1.setOrganizationIdentifier("org-1");
        cp1.setUpdatedAt(Instant.parse("2025-01-10T10:00:00Z"));
        cp1.setCredentialDataSet("{\"vc\":{}}");

        CredentialProcedure cp2 = new CredentialProcedure();
        cp2.setProcedureId(UUID.randomUUID());
        cp2.setSubject("Bob");
        cp2.setCredentialType("TYPE_B");
        cp2.setCredentialStatus(CredentialStatusEnum.ISSUED);
        cp2.setOrganizationIdentifier("org-2");
        cp2.setUpdatedAt(Instant.parse("2025-02-12T09:30:00Z"));
        cp2.setCredentialDataSet("{\"vc\":{}}");

        when(credentialProcedureRepository.findAllOrderByUpdatedDesc())
                .thenReturn(Flux.fromIterable(List.of(cp2, cp1)));

        // objectMapper.readTree is called inside toProcedureBasicInfo
        try {
            when(objectMapper.readTree("{\"vc\":{}}")).thenReturn(new ObjectMapper().readTree("{\"vc\":{}}"));
        } catch (Exception ignored) {
        }

        // When
        Mono<CredentialProcedures> mono = credentialProcedureService.getAllProceduresVisibleFor(adminOrg, true);

        // Then
        StepVerifier.create(mono)
                .assertNext(result -> {
                    List<CredentialProcedures.CredentialProcedure> list = result.credentialProcedures();
                    assertNotNull(list);
                    assertEquals(2, list.size(), "Should contain 2 procedures");

                    ProcedureBasicInfo first = list.get(0).credentialProcedure();
                    ProcedureBasicInfo second = list.get(1).credentialProcedure();

                    assertEquals(cp2.getProcedureId(), first.procedureId());
                    assertEquals("Bob", first.subject());
                    assertEquals("TYPE_B", first.credentialType());
                    assertEquals(CredentialStatusEnum.ISSUED.name(), first.status());
                    assertEquals("org-2", first.organizationIdentifier());
                    assertEquals(cp2.getUpdatedAt(), first.updated());

                    assertEquals(cp1.getProcedureId(), second.procedureId());
                    assertEquals("Alice", second.subject());
                    assertEquals("TYPE_A", second.credentialType());
                    assertEquals(CredentialStatusEnum.DRAFT.name(), second.status());
                    assertEquals("org-1", second.organizationIdentifier());
                    assertEquals(cp1.getUpdatedAt(), second.updated());
                })
                .verifyComplete();

        verify(credentialProcedureRepository, times(1)).findAllOrderByUpdatedDesc();
    }

    @Test
    void getAllProceduresVisibleFor_regularOrg_shouldDelegateToOrgSpecificMethod() {
        // Given (regular organization)
        String orgId = "org-123";

        CredentialProcedure cp = new CredentialProcedure();
        cp.setProcedureId(UUID.randomUUID());
        cp.setSubject("Carol");
        cp.setCredentialType("TYPE_C");
        cp.setCredentialStatus(CredentialStatusEnum.VALID);
        cp.setOrganizationIdentifier(orgId);
        cp.setUpdatedAt(Instant.parse("2025-03-01T08:00:00Z"));

        ProcedureBasicInfo pbi = ProcedureBasicInfo.builder()
                .procedureId(cp.getProcedureId())
                .subject(cp.getSubject())
                .credentialType(cp.getCredentialType())
                .status(cp.getCredentialStatus().name())
                .organizationIdentifier(cp.getOrganizationIdentifier())
                .updated(cp.getUpdatedAt())
                .build();

        CredentialProcedures expected = new CredentialProcedures(
                List.of(CredentialProcedures.CredentialProcedure.builder()
                        .credentialProcedure(pbi)
                        .build())
        );

        CredentialProcedureServiceImpl spyService = spy(credentialProcedureService);

        doReturn(Mono.just(expected))
                .when(spyService).getAllProceduresBasicInfoByOrganizationId(orgId);

        // When
        Mono<CredentialProcedures> mono = spyService.getAllProceduresVisibleFor(orgId, false);

        // Then
        StepVerifier.create(mono)
                .expectNextMatches(result ->
                        result.credentialProcedures().size() == 1
                                && result.credentialProcedures().get(0).credentialProcedure().procedureId().equals(cp.getProcedureId())
                                && "Carol".equals(result.credentialProcedures().get(0).credentialProcedure().subject())
                                && "TYPE_C".equals(result.credentialProcedures().get(0).credentialProcedure().credentialType())
                                && "VALID".equals(result.credentialProcedures().get(0).credentialProcedure().status())
                                && orgId.equals(result.credentialProcedures().get(0).credentialProcedure().organizationIdentifier())
                )
                .verifyComplete();

        verify(credentialProcedureRepository, never()).findAllOrderByUpdatedDesc();
        verify(spyService, times(1)).getAllProceduresBasicInfoByOrganizationId(orgId);
    }

    @Test
    void getAllProceduresBasicInfoForAllOrganizations_shouldReturnEmptyList_whenRepositoryIsEmpty() {
        // Given
        when(credentialProcedureRepository.findAllOrderByUpdatedDesc())
                .thenReturn(Flux.empty());

        // When
        Mono<CredentialProcedures> mono = credentialProcedureService.getAllProceduresVisibleFor(ADMIN_ORG_ID, true);

        // Then
        StepVerifier.create(mono)
                .assertNext(result -> {
                    List<CredentialProcedures.CredentialProcedure> list = result.credentialProcedures();
                    assertNotNull(list);
                    assertTrue(list.isEmpty(), "List should be empty");
                })
                .verifyComplete();

        verify(credentialProcedureRepository, times(1)).findAllOrderByUpdatedDesc();
    }

    @Test
    void getAllProceduresBasicInfoByOrganizationId_shouldReturnMappedList_forOrg() {
        // Given
        String orgId = "org-xyz";

        CredentialProcedure cp1 = new CredentialProcedure();
        cp1.setProcedureId(UUID.randomUUID());
        cp1.setSubject("Alice");
        cp1.setCredentialType("TYPE_A");
        cp1.setCredentialStatus(CredentialStatusEnum.DRAFT);
        cp1.setOrganizationIdentifier(orgId);
        cp1.setUpdatedAt(Instant.parse("2025-01-10T10:00:00Z"));
        cp1.setCredentialDataSet("{\"vc\":{}}");

        CredentialProcedure cp2 = new CredentialProcedure();
        cp2.setProcedureId(UUID.randomUUID());
        cp2.setSubject("Bob");
        cp2.setCredentialType("TYPE_B");
        cp2.setCredentialStatus(CredentialStatusEnum.ISSUED);
        cp2.setOrganizationIdentifier(orgId);
        cp2.setUpdatedAt(Instant.parse("2025-02-12T09:30:00Z"));
        cp2.setCredentialDataSet("{\"vc\":{}}");

        when(credentialProcedureRepository.findAllByOrganizationIdentifier(orgId))
                .thenReturn(Flux.fromIterable(List.of(cp1, cp2)));

        // objectMapper.readTree is called inside toProcedureBasicInfo
        try {
            when(objectMapper.readTree("{\"vc\":{}}")).thenReturn(new ObjectMapper().readTree("{\"vc\":{}}"));
        } catch (Exception ignored) {
        }

        // When
        Mono<CredentialProcedures> mono = credentialProcedureService.getAllProceduresBasicInfoByOrganizationId(orgId);

        // Then
        StepVerifier.create(mono)
                .assertNext(result -> {
                    List<CredentialProcedures.CredentialProcedure> list = result.credentialProcedures();
                    assertNotNull(list, "Result list should not be null");
                    assertEquals(2, list.size(), "Should contain 2 procedures");

                    ProcedureBasicInfo first = list.get(0).credentialProcedure();
                    ProcedureBasicInfo second = list.get(1).credentialProcedure();

                    assertEquals(cp1.getProcedureId(), first.procedureId());
                    assertEquals("Alice", first.subject());
                    assertEquals("TYPE_A", first.credentialType());
                    assertEquals(CredentialStatusEnum.DRAFT.name(), first.status());
                    assertEquals(orgId, first.organizationIdentifier());
                    assertEquals(cp1.getUpdatedAt(), first.updated());

                    assertEquals(cp2.getProcedureId(), second.procedureId());
                    assertEquals("Bob", second.subject());
                    assertEquals("TYPE_B", second.credentialType());
                    assertEquals(CredentialStatusEnum.ISSUED.name(), second.status());
                    assertEquals(orgId, second.organizationIdentifier());
                    assertEquals(cp2.getUpdatedAt(), second.updated());
                })
                .verifyComplete();

        verify(credentialProcedureRepository, times(1)).findAllByOrganizationIdentifier(orgId);
    }

    @Test
    void getAllProceduresBasicInfoByOrganizationId_shouldReturnEmptyList_whenRepositoryIsEmpty() {
        // Given
        String orgId = "org-empty";
        when(credentialProcedureRepository.findAllByOrganizationIdentifier(orgId))
                .thenReturn(Flux.empty());

        // When
        Mono<CredentialProcedures> mono = credentialProcedureService.getAllProceduresBasicInfoByOrganizationId(orgId);

        // Then
        StepVerifier.create(mono)
                .assertNext(result -> {
                    List<CredentialProcedures.CredentialProcedure> list = result.credentialProcedures();
                    assertNotNull(list, "Result list should not be null");
                    assertTrue(list.isEmpty(), "List should be empty");
                })
                .verifyComplete();

        verify(credentialProcedureRepository, times(1)).findAllByOrganizationIdentifier(orgId);
    }

    @Test
    void getCredentialOfferEmailInfoByProcedureId_label_usesSysTenantForOrganization() {
        // given
        String procedureId = UUID.randomUUID().toString();
        String email = "label.owner@in2.es";
        String sysTenant = "my-sys-tenant-from-config";

        CredentialProcedure cp = new CredentialProcedure();
        cp.setProcedureId(UUID.fromString(procedureId));
        cp.setCredentialType(LABEL_CREDENTIAL);
        cp.setEmail(email);
        // For LABEL, decoded JSON is not used, so it can be null
        cp.setCredentialDataSet(null);

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(cp));
        when(appConfig.getSysTenant()).thenReturn(sysTenant);

        // when
        Mono<CredentialOfferEmailNotificationInfo> mono =
                credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId);

        // then
        StepVerifier.create(mono)
                .expectNextMatches(info ->
                        email.equals(info.email()) &&
                                sysTenant.equals(info.organization()))
                .verifyComplete();

        verify(credentialProcedureRepository, times(1))
                .findByProcedureId(UUID.fromString(procedureId));
        verify(appConfig, times(1)).getSysTenant();
    }

}
