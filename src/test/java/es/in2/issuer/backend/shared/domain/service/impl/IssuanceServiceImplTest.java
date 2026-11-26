package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.ConcurrentIssuanceUpdateException;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
import es.in2.issuer.backend.shared.domain.exception.MissingCredentialTypeException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuanceServiceImplTest {

    @Mock
    private IssuancePort issuancePort;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private IssuerProperties appConfig;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;


    @Mock
    private TransactionalOperator transactionalOperator;

    @Spy
    private RecordingAuditTrail auditTrail = new RecordingAuditTrail();

    @InjectMocks
    private IssuanceServiceImpl issuanceService;

    @BeforeEach
    void passTransactionsThrough() {
        lenient().when(transactionalOperator.transactional(any(Mono.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
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

        when(issuancePort.findById(any(UUID.class)))
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

        when(issuancePort.findById(any(UUID.class)))
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

        when(issuancePort.findById(any(UUID.class)))
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

        when(issuancePort.findById(any(UUID.class)))
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

        when(issuancePort.findById(any(UUID.class)))
                .thenReturn(Mono.just(existingIssuance));
        when(issuancePort.save(any(Issuance.class)))
                .thenReturn(Mono.just(existingIssuance));

        // When
        Mono<Void> result = issuanceService.updateCredentialDataSetByIssuanceId(issuanceId, newCredential, newFormat);

        // Then
        StepVerifier.create(result).verifyComplete();

        verify(issuancePort, times(1)).findById(UUID.fromString(issuanceId));
        verify(issuancePort, times(1)).save(existingIssuance);

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

        when(issuancePort.findById(any(UUID.class)))
                .thenReturn(Mono.empty());

        // When
        Mono<Void> result = issuanceService.updateCredentialDataSetByIssuanceId(issuanceId, newCredential, newFormat);

        // Then
        StepVerifier.create(result).verifyComplete();

        verify(issuancePort, times(1)).findById(UUID.fromString(issuanceId));
        verify(issuancePort, times(0)).save(any(Issuance.class));
    }

    @Test
    void getCredentialDataSetByIssuanceId_shouldReturnCredentialDataSet() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String expectedCredentialDataSet = "{\"vc\":{\"type\":[\"TestCredentialType\"]}}";

        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.fromString(issuanceId));
        issuance.setCredentialDataSet(expectedCredentialDataSet);

        when(issuancePort.findById(any(UUID.class)))
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

        when(issuancePort.findCredentialStatusByIssuanceId(any(UUID.class)))
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

        when(issuancePort.findByCredentialStatusAndOrganizationIdentifier(
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

        when(issuancePort.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, organizationIdentifier))
                .thenReturn(Flux.empty());

        // When / Then
        StepVerifier.create(issuanceService.getAllIssuedCredentialByOrganizationIdentifier(organizationIdentifier))
                .expectNextCount(0)
                .verifyComplete();
    }

    // ---------- Admin bypass tests use boolean sysAdmin parameter ----------

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
                .build();
        when(credentialProfileRegistry.getByConfigurationId("gx.labelcredential.w3c.1"))
                .thenReturn(labelProfile);
        when(issuancePort.findByIssuanceId(UUID.fromString(issuanceId)))
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

        verify(issuancePort, times(1))
                .findByIssuanceId(UUID.fromString(issuanceId));
        verify(appConfig, times(1)).getSysTenant();
    }

    @Test
    void archiveIssuance_shouldUpdateStatusToArchivedAndSave_withoutTriggeringOtherEffects() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        String originalDataSet = "{\"vc\":{\"type\":[\"VerifiableCredential\"]}}";
        
        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.fromString(issuanceId));
        issuance.setCredentialStatus(CredentialStatusEnum.WITHDRAWN);
        issuance.setCredentialDataSet(originalDataSet);

        when(issuancePort.findByIssuanceId(UUID.fromString(issuanceId)))
                .thenReturn(Mono.just(issuance));
        when(issuancePort.save(any(Issuance.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

        // When
        Mono<Void> result = issuanceService.archiveIssuance(issuanceId);

        // Then
        StepVerifier.create(result).verifyComplete();

        verify(issuancePort, times(1)).findByIssuanceId(UUID.fromString(issuanceId));
        verify(issuancePort, times(1)).save(issuance);
        
        assertEquals(CredentialStatusEnum.ARCHIVED, issuance.getCredentialStatus());
        assertEquals(originalDataSet, issuance.getCredentialDataSet(), "archiveIssuance should not modify credential dataset");
    }

    // ---------------------------------------------------------------- SD-04 (EUD-225):
    // updateIssuanceStatusToRevoked concurrency reconciliation

    @Test
    void updateIssuanceStatusToRevoked_shouldUpdateStatusAndSave_whenTransitionIsValid() {
        // Given
        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.randomUUID());
        issuance.setCredentialStatus(CredentialStatusEnum.VALID);

        when(issuancePort.findById(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.just(issuance));

        // When
        Mono<Void> result = issuanceService.updateIssuanceStatusToRevoked(issuance);

        // Then
        StepVerifier.create(result).verifyComplete();
        assertEquals(CredentialStatusEnum.REVOKED, issuance.getCredentialStatus());
        verify(issuancePort, times(1)).save(issuance);
    }

    @Test
    void updateIssuanceStatusToRevoked_shouldReconcileAsNoop_whenLosingRaceAgainstAnAlreadyRevokedWrite() {
        // Given: two concurrent revocations (operator REST + queue consumer, ES-03) both
        // pass validateTransition against the same in-memory VALID snapshot; the version
        // column turns the loser's save() into a ConcurrentIssuanceUpdateException (mapped
        // from the infrastructure-layer optimistic-locking failure by IssuanceR2dbcAdapter).
        // Re-fetching finds the winner already persisted REVOKED.
        UUID issuanceId = UUID.randomUUID();
        Issuance staleSnapshot = new Issuance();
        staleSnapshot.setIssuanceId(issuanceId);
        staleSnapshot.setCredentialStatus(CredentialStatusEnum.VALID);

        Issuance winnerCurrentRow = new Issuance();
        winnerCurrentRow.setIssuanceId(issuanceId);
        winnerCurrentRow.setCredentialStatus(CredentialStatusEnum.REVOKED);

        when(issuancePort.save(staleSnapshot))
                .thenReturn(Mono.error(new ConcurrentIssuanceUpdateException(issuanceId, "save", new RuntimeException("stale version"))));
        when(issuancePort.findById(issuanceId)).thenReturn(Mono.just(staleSnapshot), Mono.just(winnerCurrentRow));

        // When
        Mono<Void> result = issuanceService.updateIssuanceStatusToRevoked(staleSnapshot);

        // Then: reuses the exact same "no longer revocable" signal both RevocationWorkflow
        // callers already handle end-to-end (HTTP 409 for the operator, silent skip-as-noop
        // for the queue consumer) instead of a bare optimistic-locking exception.
        StepVerifier.create(result)
                .expectErrorMatches(InvalidCredentialStatusTransitionException.class::isInstance)
                .verify();
        verify(issuancePort, times(2)).findById(issuanceId);
    }

    /** It runs inside a transaction that is attempted again: a rolled-back attempt must not block the next one. */
    @Test
    void updateIssuanceStatusToRevoked_doesNotChangeTheCallersSnapshot_soAnotherAttemptStillApplies() {
        Issuance snapshot = issuanceWithStatus(CredentialStatusEnum.VALID);
        Issuance row = new Issuance();
        row.setIssuanceId(snapshot.getIssuanceId());
        row.setCredentialStatus(CredentialStatusEnum.VALID);
        when(issuancePort.findById(snapshot.getIssuanceId())).thenReturn(Mono.just(row));
        when(issuancePort.save(row)).thenReturn(Mono.just(row));

        StepVerifier.create(issuanceService.updateIssuanceStatusToRevoked(snapshot)).verifyComplete();

        assertEquals(CredentialStatusEnum.VALID, snapshot.getCredentialStatus());
        assertEquals(CredentialStatusEnum.REVOKED, row.getCredentialStatus());
    }

    @Test
    void updateIssuanceStatusToRevoked_failsWithItsOrigin_whenTheCurrentRowIsNoLongerValid() {
        Issuance snapshot = issuanceWithStatus(CredentialStatusEnum.VALID);
        Issuance row = issuanceWithStatus(CredentialStatusEnum.REVOKED);
        when(issuancePort.findById(snapshot.getIssuanceId())).thenReturn(Mono.just(row));

        StepVerifier.create(issuanceService.updateIssuanceStatusToRevoked(snapshot))
                .expectErrorSatisfies(e -> assertEquals(CredentialStatusEnum.REVOKED,
                        ((InvalidCredentialStatusTransitionException) e).getFrom()))
                .verify();

        verify(issuancePort, never()).save(any());
    }

    @Test
    void updateIssuanceStatusToRevoked_shouldPropagateConflict_whenCurrentStatusIsGenuinelyUnexpected() {
        // Given: the conflict is not explained by the known "already revoked by the other
        // path" race -- it must not be papered over as a no-op.
        UUID issuanceId = UUID.randomUUID();
        Issuance staleSnapshot = new Issuance();
        staleSnapshot.setIssuanceId(issuanceId);
        staleSnapshot.setCredentialStatus(CredentialStatusEnum.VALID);

        Issuance unexpectedCurrentRow = new Issuance();
        unexpectedCurrentRow.setIssuanceId(issuanceId);
        unexpectedCurrentRow.setCredentialStatus(CredentialStatusEnum.EXPIRED);

        ConcurrentIssuanceUpdateException conflict =
                new ConcurrentIssuanceUpdateException(issuanceId, "save", new RuntimeException("stale version"));
        when(issuancePort.save(staleSnapshot)).thenReturn(Mono.error(conflict));
        when(issuancePort.findById(issuanceId)).thenReturn(Mono.just(staleSnapshot), Mono.just(unexpectedCurrentRow));

        // When
        Mono<Void> result = issuanceService.updateIssuanceStatusToRevoked(staleSnapshot);

        // Then
        StepVerifier.create(result)
                .expectErrorMatches(conflict::equals)
                .verify();
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SYS_TENANT = "sys-tenant";

    private static Issuance issuanceWithStatus(CredentialStatusEnum status) {
        Issuance issuance = new Issuance();
        issuance.setIssuanceId(UUID.randomUUID());
        issuance.setCredentialStatus(status);
        return issuance;
    }

    private static ConcurrentIssuanceUpdateException staleVersion(UUID issuanceId) {
        return new ConcurrentIssuanceUpdateException(issuanceId, "save", new RuntimeException("stale version"));
    }

    private static boolean isConflictDuring(Throwable error, String operation) {
        return error instanceof ConcurrentIssuanceUpdateException && error.getMessage().endsWith("during " + operation);
    }

    @Test
    void getCredentialTypeByIssuanceId_shouldReadTopLevelType_whenThereIsNoVcWrapper() throws Exception {
        String dataSet = "{\"type\":[\"VerifiableCredential\",\"TopLevelType\"]}";
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.ISSUED);
        issuance.setCredentialDataSet(dataSet);
        when(issuancePort.findById(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(objectMapper.readTree(dataSet)).thenReturn(JSON.readTree(dataSet));

        StepVerifier.create(issuanceService.getCredentialTypeByIssuanceId(issuance.getIssuanceId().toString()))
                .expectNext("TopLevelType")
                .verifyComplete();
    }

    @Test
    void getCredentialTypeByIssuanceId_shouldError_whenTypeIsNotAnArray() throws Exception {
        String dataSet = "{\"vc\":{\"type\":\"TestType\"}}";
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.ISSUED);
        issuance.setCredentialDataSet(dataSet);
        when(issuancePort.findById(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(objectMapper.readTree(dataSet)).thenReturn(JSON.readTree(dataSet));

        StepVerifier.create(issuanceService.getCredentialTypeByIssuanceId(issuance.getIssuanceId().toString()))
                .expectError(MissingCredentialTypeException.class)
                .verify();
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "{\"vc\":{\"id\":\"urn:vc\"},\"id\":\"urn:top\",\"jti\":\"jti-1\"} | urn:vc",
            "{\"vc\":{\"id\":\" \"},\"id\":\"urn:top\",\"jti\":\"jti-1\"}    | urn:top",
            "{\"id\":\"\",\"jti\":\"jti-1\"}                                 | jti-1"
    })
    void extractCredentialId_shouldPreferVcIdThenTopLevelIdThenJti(String dataSet, String expectedId) throws Exception {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.ISSUED);
        issuance.setCredentialDataSet(dataSet);
        when(objectMapper.readTree(dataSet)).thenReturn(JSON.readTree(dataSet));

        StepVerifier.create(issuanceService.extractCredentialId(issuance))
                .expectNext(expectedId)
                .verifyComplete();
    }

    @Test
    void extractCredentialId_shouldCompleteEmpty_whenTheCredentialHasNoId() throws Exception {
        String dataSet = "{\"vc\":{}}";
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.ISSUED);
        issuance.setCredentialDataSet(dataSet);
        when(objectMapper.readTree(dataSet)).thenReturn(JSON.readTree(dataSet));

        StepVerifier.create(issuanceService.extractCredentialId(issuance)).verifyComplete();
    }

    @Test
    void updateCredentialDataSetByIssuanceId_shouldReportTheOperation_whenTheSaveLosesARace() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        when(issuancePort.findById(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.error(staleVersion(issuance.getIssuanceId())));

        StepVerifier.create(issuanceService.updateCredentialDataSetByIssuanceId(issuance.getIssuanceId().toString(), "{}", "jwt_vc_json"))
                .expectErrorMatches(error -> isConflictDuring(error, "updateCredentialDataSetByIssuanceId"))
                .verify();
    }

    @Test
    void updateIssuanceStatusToValidByIssuanceId_shouldActivateAnIssuedCredential() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.ISSUED);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.just(issuance));

        StepVerifier.create(issuanceService.updateIssuanceStatusToValidByIssuanceId(issuance.getIssuanceId().toString()))
                .verifyComplete();
        assertEquals(CredentialStatusEnum.VALID, issuance.getCredentialStatus());
    }

    @Test
    void updateIssuanceStatusToValidByIssuanceId_shouldRejectAnInvalidTransition() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));

        StepVerifier.create(issuanceService.updateIssuanceStatusToValidByIssuanceId(issuance.getIssuanceId().toString()))
                .expectError(InvalidCredentialStatusTransitionException.class)
                .verify();
        verify(issuancePort, never()).save(any(Issuance.class));
    }

    @Test
    void updateIssuanceStatusToValidByIssuanceId_shouldReportTheOperation_whenTheSaveLosesARace() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.ISSUED);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.error(staleVersion(issuance.getIssuanceId())));

        StepVerifier.create(issuanceService.updateIssuanceStatusToValidByIssuanceId(issuance.getIssuanceId().toString()))
                .expectErrorMatches(error -> isConflictDuring(error, "updateIssuanceStatusToValidByIssuanceId"))
                .verify();
    }

    @Test
    void updateIssuanceStatusToRevoked_shouldPropagateConflict_whenTheIssuanceIsGoneOnRefetch() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.VALID);
        ConcurrentIssuanceUpdateException conflict = staleVersion(issuance.getIssuanceId());
        when(issuancePort.save(issuance)).thenReturn(Mono.error(conflict));
        when(issuancePort.findById(issuance.getIssuanceId())).thenReturn(Mono.just(issuance), Mono.empty());

        StepVerifier.create(issuanceService.updateIssuanceStatusToRevoked(issuance))
                .expectErrorMatches(conflict::equals)
                .verify();
    }

    @Test
    void withdrawIssuance_shouldWithdrawADraft() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.just(issuance));

        StepVerifier.create(issuanceService.withdrawIssuance(issuance.getIssuanceId().toString())).verifyComplete();
        assertEquals(CredentialStatusEnum.WITHDRAWN, issuance.getCredentialStatus());
    }

    @Test
    void withdrawIssuance_draft_stagesIssuanceWithdrawnInTheTransactionOfTheChange() {
        // Arrange
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.just(issuance));

        // Act
        Mono<Void> withdrawn = issuanceService.withdrawIssuance(issuance.getIssuanceId().toString());

        // Assert
        StepVerifier.create(withdrawn).verifyComplete();
        AuditEntry entry = auditTrail.staged().getFirst();
        assertEquals(AuditEventType.ISSUANCE_WITHDRAWN, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("issuance:" + issuance.getIssuanceId(), entry.resource());
        assertTrue(entry.details().isEmpty());
        assertTrue(auditTrail.stagedInNewTransaction().isEmpty());
    }

    @Test
    void withdrawIssuance_issuanceNotInDraft_stagesDeniedInvalidStatusAndKeepsTheError() {
        // Arrange
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.VALID);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));

        // Act
        Mono<Void> withdrawn = issuanceService.withdrawIssuance(issuance.getIssuanceId().toString());

        // Assert
        StepVerifier.create(withdrawn).expectError(InvalidCredentialStatusTransitionException.class).verify();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditEventType.ISSUANCE_WITHDRAWN, entry.type());
        assertEquals(AuditResult.DENIED, entry.result());
        assertEquals("InvalidStatus", entry.reason());
        assertTrue(auditTrail.staged().isEmpty());
    }

    @Test
    void withdrawIssuance_saveLosesARace_stagesNothingBecauseTheConflictHasNoCatalogueReason() {
        // Arrange
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.error(staleVersion(issuance.getIssuanceId())));

        // Act
        Mono<Void> withdrawn = issuanceService.withdrawIssuance(issuance.getIssuanceId().toString());

        // Assert
        StepVerifier.create(withdrawn).expectErrorMatches(error -> isConflictDuring(error, "withdrawIssuance")).verify();
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void archiveIssuance_withdrawnProcess_stagesIssuanceArchivedInTheTransactionOfTheChange() {
        // Arrange
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.WITHDRAWN);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.just(issuance));

        // Act
        Mono<Void> archived = issuanceService.archiveIssuance(issuance.getIssuanceId().toString());

        // Assert
        StepVerifier.create(archived).verifyComplete();
        AuditEntry entry = auditTrail.staged().getFirst();
        assertEquals(AuditEventType.ISSUANCE_ARCHIVED, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
    }

    @Test
    void archiveIssuance_processStillInDraft_stagesDeniedInvalidStatus() {
        // Arrange
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));

        // Act
        Mono<Void> archived = issuanceService.archiveIssuance(issuance.getIssuanceId().toString());

        // Assert
        StepVerifier.create(archived).expectError(InvalidCredentialStatusTransitionException.class).verify();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditEventType.ISSUANCE_ARCHIVED, entry.type());
        assertEquals("InvalidStatus", entry.reason());
    }

    @Test
    void withdrawIssuance_shouldReportTheOperation_whenTheSaveLosesARace() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.error(staleVersion(issuance.getIssuanceId())));

        StepVerifier.create(issuanceService.withdrawIssuance(issuance.getIssuanceId().toString()))
                .expectErrorMatches(error -> isConflictDuring(error, "withdrawIssuance"))
                .verify();
    }

    @Test
    void archiveIssuance_shouldReportTheOperation_whenTheSaveLosesARace() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.WITHDRAWN);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.error(staleVersion(issuance.getIssuanceId())));

        StepVerifier.create(issuanceService.archiveIssuance(issuance.getIssuanceId().toString()))
                .expectErrorMatches(error -> isConflictDuring(error, "archiveIssuance"))
                .verify();
    }

    @Test
    void findCredentialOfferEmailInfoByIssuanceId_shouldError_whenTheConfigurationIsUnknown() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        issuance.setCredentialType("unknown.type.1");
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(credentialProfileRegistry.getByConfigurationId("unknown.type.1")).thenReturn(null);

        StepVerifier.create(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuance.getIssuanceId().toString()))
                .expectError(FormatUnsupportedException.class)
                .verify();
    }

    @Test
    void findCredentialOfferEmailInfoByIssuanceId_shouldUseTheSysTenant_whenTheTypeHasNoMandator() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        issuance.setCredentialType("doctorid.sd.1");
        issuance.setEmail("owner@example.com");
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(credentialProfileRegistry.getByConfigurationId("doctorid.sd.1")).thenReturn(CredentialProfile.builder()
                .build());
        when(appConfig.getSysTenant()).thenReturn(SYS_TENANT);

        StepVerifier.create(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuance.getIssuanceId().toString()))
                .assertNext(info -> assertEquals(SYS_TENANT, info.organization()))
                .verifyComplete();
    }

    private Mono<CredentialOfferEmailNotificationInfo> emailInfoForMandatorCredential(
            CredentialProfile.Validation validation, String dataSet) throws Exception {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        issuance.setCredentialType("learcredential.employee.w3c.4");
        issuance.setEmail("owner@example.com");
        issuance.setCredentialDataSet(dataSet);
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(credentialProfileRegistry.getByConfigurationId("learcredential.employee.w3c.4")).thenReturn(CredentialProfile.builder()
                .validation(validation)
                .build());
        // Only parsed when the type has a mandator path to read the organization name from.
        lenient().when(objectMapper.readTree(dataSet)).thenReturn(JSON.readTree(dataSet));
        return issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuance.getIssuanceId().toString());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organization\":\"ACME\"}}}} | ACME",
            "{\"credentialSubject\":{\"mandate\":{\"mandator\":{}}}}                         | sys-tenant",
            "{\"credentialSubject\":{}}                                                       | sys-tenant"
    })
    void findCredentialOfferEmailInfoByIssuanceId_shouldReadTheMandatorOrganization_orFallBackToTheSysTenant(
            String dataSet, String expectedOrganization) throws Exception {
        lenient().when(appConfig.getSysTenant()).thenReturn(SYS_TENANT);

        StepVerifier.create(emailInfoForMandatorCredential(
                        new CredentialProfile.Validation("credentialSubject.mandate.mandator.organizationIdentifier"), dataSet))
                .assertNext(info -> {
                    assertEquals(expectedOrganization, info.organization());
                    assertEquals("owner@example.com", info.email());
                })
                .verifyComplete();
    }

    @ParameterizedTest
    @CsvSource(value = {"NO_VALIDATION", "NO_PATH", "organizationIdentifier"})
    void findCredentialOfferEmailInfoByIssuanceId_shouldUseTheSysTenant_whenNoMandatorPathCanBeDerived(String orgIdPath) throws Exception {
        CredentialProfile.Validation validation = switch (orgIdPath) {
            case "NO_VALIDATION" -> null;
            case "NO_PATH" -> new CredentialProfile.Validation(null);
            default -> new CredentialProfile.Validation(orgIdPath);
        };
        when(appConfig.getSysTenant()).thenReturn(SYS_TENANT);

        StepVerifier.create(emailInfoForMandatorCredential(validation, "{\"organization\":\"ACME\"}"))
                .assertNext(info -> assertEquals(SYS_TENANT, info.organization()))
                .verifyComplete();
    }

    @Test
    void findCredentialOfferEmailInfoByIssuanceId_shouldError_whenTheCredentialIsNotValidJson() throws Exception {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        issuance.setCredentialType("learcredential.employee.w3c.4");
        issuance.setCredentialDataSet("{");
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(credentialProfileRegistry.getByConfigurationId("learcredential.employee.w3c.4")).thenReturn(CredentialProfile.builder()
                .validation(new CredentialProfile.Validation("credentialSubject.mandate.mandator.organizationIdentifier"))
                .build());
        when(objectMapper.readTree("{")).thenThrow(new JsonParseException(null, "unexpected end"));

        StepVerifier.create(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuance.getIssuanceId().toString()))
                .expectError(ParseCredentialJsonException.class)
                .verify();
    }

    @Test
    void updateIssuance_shouldSaveTheIssuance() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        when(issuancePort.save(issuance)).thenReturn(Mono.just(issuance));

        StepVerifier.create(issuanceService.updateIssuance(issuance)).expectNext(issuance).verifyComplete();
    }

    @Test
    void updateIssuance_shouldReportTheOperation_whenTheSaveLosesARace() {
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.DRAFT);
        when(issuancePort.save(issuance)).thenReturn(Mono.error(staleVersion(issuance.getIssuanceId())));

        StepVerifier.create(issuanceService.updateIssuance(issuance))
                .expectErrorMatches(error -> isConflictDuring(error, "updateIssuance"))
                .verify();
    }

    @Test
    void lookupQueries_shouldDelegateToThePort() {
        Instant cutoff = Instant.parse("2025-01-01T00:00:00Z");
        Issuance issuance = issuanceWithStatus(CredentialStatusEnum.ISSUED);
        when(issuancePort.findByCredentialOfferRefreshToken("refresh-token")).thenReturn(Mono.just(issuance));
        when(issuancePort.findIssuedReadyForActivation(CredentialStatusEnum.ISSUED, cutoff)).thenReturn(Flux.just(issuance));
        when(issuancePort.findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum.DRAFT, cutoff)).thenReturn(Flux.just(issuance));
        when(issuancePort.findFailedDeliveries(cutoff)).thenReturn(Flux.just(issuance));

        StepVerifier.create(issuanceService.getIssuanceByCredentialOfferRefreshToken("refresh-token")).expectNext(issuance).verifyComplete();
        StepVerifier.create(issuanceService.findIssuedReadyForActivation(cutoff)).expectNext(issuance).verifyComplete();
        StepVerifier.create(issuanceService.findStaleDrafts(cutoff)).expectNext(issuance).verifyComplete();
        StepVerifier.create(issuanceService.findFailedDeliveries(cutoff)).expectNext(issuance).verifyComplete();
    }

}
