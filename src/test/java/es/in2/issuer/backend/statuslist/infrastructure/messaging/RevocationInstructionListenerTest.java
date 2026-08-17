package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.statuslist.application.HandleRevocationInstructionWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction;
import es.in2.issuer.backend.statuslist.domain.model.TenantBindingResolution;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.config.RevocationMessagingConfig.RevocationMessagingProperties;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.dto.RevocationInstructionMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * F12 (EUD-225 {@code /verify}): fast, mocked regression for the exact wiring bug the
 * finding described -- environment-suffix stripping must never touch the raw value fed
 * into {@code RevocationTenantBinding.resolve()} (the mismatch comparison itself), only
 * the tenant derived afterward for the {@code tenant_registry} lookup.
 * {@code RevocationInstructionSingleTenantIT} covers the broker-backed happy/mismatch
 * paths end-to-end against a real tenant; this covers the specific env-suffix wiring at
 * unit speed, including the one truth-table row (a suffixed {@code tenant-binding} value)
 * that would otherwise need a third Testcontainers Spring context to reach.
 */
@ExtendWith(MockitoExtension.class)
class RevocationInstructionListenerTest {

    private static final String ISSUANCE_ID = "6f1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";

    @Mock
    private RevocationInstructionMessageMapper mapper;
    @Mock
    private HandleRevocationInstructionWorkflow workflow;
    @Mock
    private RevocationInstructionErrorClassifier errorClassifier;
    @Mock
    private TenantRegistryService tenantRegistryService;

    private static RevocationInstructionMessage rawMessage(String tenantId) {
        return new RevocationInstructionMessage(
                "revocation-instruction/v1", "msg-1", tenantId, ISSUANCE_ID, null, null);
    }

    @Test
    void onMessage_envSuffixedMessageTenantId_isRejectedAsMismatchNotSilentlyAccepted() {
        // tenant-binding=e2e-tenant-a (bare), message declares e2e-tenant-a-stg: must be
        // Mismatch. Stripping the message's suffix before the comparison would make this a
        // false FromMessage match -- fail-open, exactly the F12 bug.
        RevocationMessagingProperties properties = new RevocationMessagingProperties(true, "e2e-tenant-a");
        RevocationInstructionListener listener = new RevocationInstructionListener(
                mapper, workflow, errorClassifier, tenantRegistryService, properties);

        RevocationInstruction instruction = new RevocationInstruction(
                "msg-1", "e2e-tenant-a-stg", ISSUANCE_ID, null, Instant.now());
        when(mapper.toDomain(any(), any(), any())).thenReturn(instruction);
        when(workflow.handleRevocationInstruction(anyString(), eq(instruction), any()))
                .thenReturn(Mono.empty());

        listener.onMessage(rawMessage("e2e-tenant-a-stg"), null);

        ArgumentCaptor<TenantBindingResolution> resolutionCaptor = ArgumentCaptor.forClass(TenantBindingResolution.class);
        verify(workflow).handleRevocationInstruction(anyString(), eq(instruction), resolutionCaptor.capture());
        assertThat(resolutionCaptor.getValue()).isInstanceOf(TenantBindingResolution.Mismatch.class);
        TenantBindingResolution.Mismatch mismatch = (TenantBindingResolution.Mismatch) resolutionCaptor.getValue();
        assertThat(mismatch.declaredInMessage()).isEqualTo("e2e-tenant-a-stg");
        assertThat(mismatch.configured()).isEqualTo("e2e-tenant-a");
        // Mismatch never needs the registry (see buildPipeline) -- confirms this branch
        // was taken, not a FromMessage/FromDeployment path that happened to also succeed.
        verifyNoInteractions(tenantRegistryService);
    }

    @Test
    void onMessage_envSuffixedBindingMatchingEnvSuffixedMessage_isAcceptedAsFromMessage() {
        // tenant-binding=e2e-tenant-a-stg, message also declares e2e-tenant-a-stg (identical
        // raw strings): must be FromMessage (accepted), not a spurious Mismatch -- the
        // asymmetric bug (stripping only the message side) would otherwise reject this.
        RevocationMessagingProperties properties = new RevocationMessagingProperties(true, "e2e-tenant-a-stg");
        RevocationInstructionListener listener = new RevocationInstructionListener(
                mapper, workflow, errorClassifier, tenantRegistryService, properties);

        RevocationInstruction instruction = new RevocationInstruction(
                "msg-1", "e2e-tenant-a-stg", ISSUANCE_ID, null, Instant.now());
        when(mapper.toDomain(any(), any(), any())).thenReturn(instruction);
        // Registry knows the tenant only by its bare (stripped) name -- same convention as
        // TenantDomainWebFilter's environment-agnostic schema naming.
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("e2e-tenant-a")));
        when(workflow.handleRevocationInstruction(anyString(), eq(instruction), any()))
                .thenReturn(Mono.empty());

        listener.onMessage(rawMessage("e2e-tenant-a-stg"), null);

        ArgumentCaptor<TenantBindingResolution> resolutionCaptor = ArgumentCaptor.forClass(TenantBindingResolution.class);
        verify(workflow).handleRevocationInstruction(anyString(), eq(instruction), resolutionCaptor.capture());
        assertThat(resolutionCaptor.getValue()).isInstanceOf(TenantBindingResolution.FromMessage.class);
        // Reaching the workflow call at all proves the registry lookup succeeded against
        // the *stripped* tenant (e2e-tenant-a) -- an unstripped lookup against
        // e2e-tenant-a-stg would have failed against the mocked registry above.
        verify(tenantRegistryService).getActiveTenantSchemas();
    }
}
