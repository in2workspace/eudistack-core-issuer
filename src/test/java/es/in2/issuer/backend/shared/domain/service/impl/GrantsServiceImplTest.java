package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.model.dto.TxCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GrantsServiceImplTest {

    @Mock
    private PreAuthorizedCodeService preAuthorizedCodeService;

    @InjectMocks
    private GrantsServiceImpl grantsService;

    @Test
    void shouldGenerateBothGrants() {
        String preAuthCode = "pre-auth-code-123";
        String pin = "4567";
        PreAuthorizedCodeResponse preAuthResponse = PreAuthorizedCodeResponse.builder()
                .preAuthorizedCode(preAuthCode)
                .txCode(TxCode.builder().length(4).inputMode("numeric").build())
                .pin(pin)
                .build();

        when(preAuthorizedCodeService.generatePreAuthorizedCode(anyString(), any()))
                .thenReturn(Mono.just(preAuthResponse));

        StepVerifier.create(grantsService.generateGrants("test-process", Mono.just("procedure-id")))
                .assertNext(result -> {
                    assertNotNull(result.grants().authorizationCode());
                    assertNotNull(result.grants().authorizationCode().issuerState());
                    assertEquals(preAuthCode, result.grants().preAuthorizedCode().preAuthorizedCode());
                    assertNotNull(result.grants().preAuthorizedCode().txCode());
                    assertEquals(pin, result.txCodeValue());
                })
                .verifyComplete();
    }
}
