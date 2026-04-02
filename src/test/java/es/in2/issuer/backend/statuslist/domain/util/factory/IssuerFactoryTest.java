package es.in2.issuer.backend.statuslist.domain.util.factory;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.TimeoutException;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class IssuerFactoryTest {

    @Mock private QtspIssuerService qtspIssuerService;
    @InjectMocks private IssuerFactory issuerFactory;

    @Test
    void createDetailedIssuer_Remote_SuccessPath() {
        DetailedIssuer expected = DetailedIssuer.builder()
                .id("id1")
                .organizationIdentifier("org1")
                .organization("o")
                .country("ES")
                .commonName("CN")
                .serialNumber("SN")
                .build();

        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.just(expected));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectNext(expected)
                .verifyComplete();

        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
    }

    @Test
    void createSimpleIssuer_Remote_SuccessPath() {
        DetailedIssuer detailed = DetailedIssuer.builder()
                .id("issuer-id")
                .build();

        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.just(detailed));

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> assertEquals("issuer-id", simple.getId()))
                .verifyComplete();

        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
    }

    @Test
    void createDetailedIssuer_Remote_Error_PropagatesError() {
        RemoteSignatureException ex = new RemoteSignatureException("boom");
        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(ex));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectErrorSatisfies(err -> assertEquals(ex, err))
                .verify();

        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
    }

    @Test
    void createDetailedIssuer_Remote_RecoverableErrors_ThenRetryExhausted() {
        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new TimeoutException("t1")))
                .thenReturn(Mono.error(new TimeoutException("t2")))
                .thenReturn(Mono.error(new TimeoutException("t3")))
                .thenReturn(Mono.error(new TimeoutException("t4")));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectErrorSatisfies(err -> {
                    assertEquals("reactor.core.Exceptions$RetryExhaustedException", err.getClass().getName());
                    assertEquals(TimeoutException.class, err.getCause().getClass());
                })
                .verify();

        verify(qtspIssuerService, times(1)).resolveRemoteDetailedIssuer();
    }

    @Test
    void createSimpleIssuer_Remote_Success_MapsToSimpleIssuer() {
        DetailedIssuer detailed = DetailedIssuer.builder()
                .id("did:elsi:ABC")
                .build();

        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.just(detailed));

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> assertEquals("did:elsi:ABC", simple.getId()))
                .verifyComplete();

        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
    }
}
