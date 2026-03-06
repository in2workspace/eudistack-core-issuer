package es.in2.issuer.backend.statuslist.infrastructure.controller;

import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class TokenStatusListControllerTest {

    private StatusListWorkflow statusListWorkflow;
    private TokenStatusListController controller;

    @BeforeEach
    void setUp() {
        statusListWorkflow = mock(StatusListWorkflow.class);
        controller = new TokenStatusListController(statusListWorkflow);
    }

    @Test
    void getTokenStatusList_whenOk_returnsResponseEntityWithStatuslistJwt() {
        long listId = 42L;
        String jwt = "header.payload.signature";

        when(statusListWorkflow.getSignedStatusListCredential(listId)).thenReturn(Mono.just(jwt));

        Mono<ResponseEntity<String>> result = controller.getTokenStatusList(listId);

        StepVerifier.create(result)
                .assertNext(res -> {
                    assertThat(res.getStatusCode().value()).isEqualTo(200);
                    assertThat(res.getHeaders().getContentType())
                            .isEqualTo(MediaType.parseMediaType("application/statuslist+jwt"));
                    assertThat(res.getBody()).isEqualTo(jwt);
                })
                .verifyComplete();

        verify(statusListWorkflow).getSignedStatusListCredential(listId);
    }

    @Test
    void getTokenStatusList_whenWorkflowFails_propagatesError() {
        long listId = 42L;

        when(statusListWorkflow.getSignedStatusListCredential(listId))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(controller.getTokenStatusList(listId))
                .expectError(RuntimeException.class)
                .verify();

        verify(statusListWorkflow).getSignedStatusListCredential(listId);
    }
}
