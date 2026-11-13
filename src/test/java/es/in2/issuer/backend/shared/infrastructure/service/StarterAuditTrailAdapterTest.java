package es.in2.issuer.backend.shared.infrastructure.service;

import com.eudistack.auditoria.application.ReactiveAuditPublisher;
import com.eudistack.auditoria.domain.AuditDraft;
import com.eudistack.auditoria.domain.AuditResult;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.ReactiveTransaction;
import org.springframework.transaction.ReactiveTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class StarterAuditTrailAdapterTest {

    private final ReactiveAuditPublisher publisher = mock(ReactiveAuditPublisher.class);
    private final ReactiveTransactionManager transactionManager = mock(ReactiveTransactionManager.class);
    private StarterAuditTrailAdapter adapter;

    @BeforeEach
    void setUp() {
        ReactiveTransaction transaction = mock(ReactiveTransaction.class);
        when(transactionManager.getReactiveTransaction(any())).thenReturn(Mono.just(transaction));
        when(transactionManager.commit(transaction)).thenReturn(Mono.empty());
        when(publisher.stage(any())).thenReturn(Mono.empty());
        adapter = new StarterAuditTrailAdapter(publisher, transactionManager);
    }

    @Test
    void stage_successEntry_handsTheFactToThePublisherAsSuccess() {
        // Arrange
        AuditEntry entry = AuditEntry.success(AuditEventType.ISSUANCE_REQUESTED, "issuance:1", Map.of("attestation_type", "type"));

        // Act
        StepVerifier.create(adapter.stage(entry)).verifyComplete();

        // Assert
        ArgumentCaptor<AuditDraft> draft = ArgumentCaptor.forClass(AuditDraft.class);
        verify(publisher).stage(draft.capture());
        assertEquals(AuditResult.SUCCESS, draft.getValue().result());
        assertNull(draft.getValue().reason());
        assertEquals("IssuanceRequested", draft.getValue().fact().eventType());
        assertEquals("Issue", draft.getValue().fact().action());
        assertEquals("issuance:1", draft.getValue().fact().resource());
        assertEquals("issuer", draft.getValue().fact().source());
        assertEquals(Map.of("attestation_type", "type"), draft.getValue().fact().details());
        verifyNoInteractions(transactionManager);
    }

    @Test
    void stage_deniedEntry_keepsTheReasonAndTheSourceOfItsType() {
        // Arrange
        AuditEntry entry = AuditEntry.forReason(AuditEventType.REVOCATION, "issuance:1", "AlreadyRevoked", Map.of());

        // Act
        StepVerifier.create(adapter.stage(entry)).verifyComplete();

        // Assert
        ArgumentCaptor<AuditDraft> draft = ArgumentCaptor.forClass(AuditDraft.class);
        verify(publisher).stage(draft.capture());
        assertEquals(AuditResult.DENIED, draft.getValue().result());
        assertEquals("AlreadyRevoked", draft.getValue().reason());
    }

    @Test
    void stage_publisherFails_propagatesTheError() {
        // Arrange
        when(publisher.stage(any())).thenReturn(Mono.error(new IllegalStateException("no transaction")));
        AuditEntry entry = AuditEntry.success(AuditEventType.ISSUANCE_REQUESTED, "issuance:1", Map.of());

        // Act & Assert
        StepVerifier.create(adapter.stage(entry)).expectError(IllegalStateException.class).verify();
    }

    @Test
    void stageInNewTransaction_entry_opensATransactionOfItsOwnAroundTheStaging() {
        // Arrange
        AuditEntry entry = AuditEntry.success(AuditEventType.ISSUANCE_QUERIED, "issuance-list:org", Map.of());

        // Act
        StepVerifier.create(adapter.stageInNewTransaction(entry)).verifyComplete();

        // Assert
        ArgumentCaptor<TransactionDefinition> definition = ArgumentCaptor.forClass(TransactionDefinition.class);
        verify(transactionManager).getReactiveTransaction(definition.capture());
        assertEquals(TransactionDefinition.PROPAGATION_REQUIRES_NEW, definition.getValue().getPropagationBehavior());
        verify(publisher).stage(any());
    }

    @Test
    void asHolder_requestWithoutTenant_runsTheFlowUnchanged() {
        // Arrange
        Mono<String> flow = Mono.just("result");

        // Act & Assert
        StepVerifier.create(adapter.asHolder("issuance-1", flow)).expectNext("result").verifyComplete();
    }
}
