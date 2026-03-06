package es.in2.issuer.backend.statuslist.application;


import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StatusListWorkflowTest {

    @Mock
    private StatusListProvider statusListProvider;

    private StatusListWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new StatusListWorkflow(statusListProvider);
    }

    @Test
    void allocateEntry_whenSuccess_returnsEntryAndCallsProvider() {
        StatusPurpose purpose = mock(StatusPurpose.class);
        StatusListFormat format = StatusListFormat.BITSTRING_VC;
        String procedureId = "proc-123";
        String token = "token-abc";

        StatusListEntry entry = mock(StatusListEntry.class);
        when(entry.statusListCredential()).thenReturn("https://issuer.example/status-list/55");
        when(entry.statusListIndex()).thenReturn("7");

        when(statusListProvider.allocateEntry(purpose, format, procedureId, token))
                .thenReturn(Mono.just(entry));

        StepVerifier.create(workflow.allocateEntry(purpose, format, procedureId, token))
                .expectNext(entry)
                .verifyComplete();

        verify(statusListProvider).allocateEntry(purpose, format, procedureId, token);
        verifyNoMoreInteractions(statusListProvider);
    }


    @Test
    void allocateEntry_whenProviderErrors_propagatesErrorAndCallsProvider() {
        StatusPurpose purpose = mock(StatusPurpose.class);
        StatusListFormat format = StatusListFormat.BITSTRING_VC;
        String procedureId = "proc-123";
        String token = "token-abc";

        RuntimeException ex = new RuntimeException("boom");

        when(statusListProvider.allocateEntry(purpose, format, procedureId, token))
                .thenReturn(Mono.error(ex));

        StepVerifier.create(workflow.allocateEntry(purpose, format, procedureId, token))
                .expectErrorMatches(e -> e instanceof RuntimeException && "boom".equals(e.getMessage()))
                .verify();

        verify(statusListProvider).allocateEntry(purpose, format, procedureId, token);
        verifyNoMoreInteractions(statusListProvider);
    }

    @Test
    void allocateEntry_whenPurposeIsNull_throwsAndDoesNotCallProvider() {
        StatusListFormat format = StatusListFormat.BITSTRING_VC;
        String procedureId = "proc-123";
        String token = "token-abc";

        assertThrows(RuntimeException.class, () -> workflow.allocateEntry(null, format, procedureId, token));

        verifyNoInteractions(statusListProvider);
    }

    @Test
    void allocateEntry_tokenJwtFormat_delegatesToProvider() {
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        StatusListFormat format = StatusListFormat.TOKEN_JWT;
        String procedureId = "proc-456";
        String token = "token-xyz";

        StatusListEntry entry = StatusListEntry.builder()
                .id("https://issuer.example/token/v1/credentials/status/10#5")
                .type("TokenStatusList")
                .statusPurpose(purpose)
                .statusListIndex("5")
                .statusListCredential("https://issuer.example/token/v1/credentials/status/10")
                .build();

        when(statusListProvider.allocateEntry(purpose, format, procedureId, token))
                .thenReturn(Mono.just(entry));

        StepVerifier.create(workflow.allocateEntry(purpose, format, procedureId, token))
                .assertNext(e -> {
                    assertEquals("TokenStatusList", e.type());
                    assertEquals("5", e.statusListIndex());
                })
                .verifyComplete();

        verify(statusListProvider).allocateEntry(purpose, format, procedureId, token);
    }

    @Test
    void getSignedStatusListCredential_whenSuccess_returnsCredentialAndCallsProvider() {
        Long listId = 10L;
        String signed = "signed-credential";

        when(statusListProvider.getSignedStatusListCredential(listId))
                .thenReturn(Mono.just(signed));

        StepVerifier.create(workflow.getSignedStatusListCredential(listId))
                .expectNext(signed)
                .verifyComplete();

        verify(statusListProvider).getSignedStatusListCredential(listId);
        verifyNoMoreInteractions(statusListProvider);
    }

    @Test
    void getSignedStatusListCredential_whenListIdIsNull_throwsAndDoesNotCallProvider() {
        assertThrows(RuntimeException.class, () -> workflow.getSignedStatusListCredential(null));

        verifyNoInteractions(statusListProvider);
    }

}
