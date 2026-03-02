package es.in2.issuer.backend.shared.domain.util.factory;


import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.service.SigningRecoveryService;
import es.in2.issuer.backend.signing.domain.model.port.SignerConfig;
import es.in2.issuer.backend.signing.domain.model.port.SigningRuntimeProperties;
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
import static es.in2.issuer.backend.shared.domain.util.Constants.DID_ELSI;
import static org.junit.jupiter.api.Assertions.assertEquals;


@ExtendWith(MockitoExtension.class)
class IssuerFactoryTest {

    @Mock private SignerConfig signerConfig;
    @Mock private SigningRecoveryService signingRecoveryService;
    @Mock private QtspIssuerService qtspIssuerService;
    @Mock private SigningRuntimeProperties signingRuntimeProperties;

    @InjectMocks private IssuerFactory issuerFactory;

    private final String procedureId = "proc-123";

    @Test
    void createDetailedIssuer_LocalServerSide_ReturnsFromDefaultConfig() {
        when(signingRuntimeProperties.getProvider()).thenReturn("in-memory");

        when(signerConfig.getOrganizationIdentifier()).thenReturn("ORG-ID");
        when(signerConfig.getOrganization()).thenReturn("MyOrg");
        when(signerConfig.getCountry()).thenReturn("ES");
        when(signerConfig.getCommonName()).thenReturn("CN");
        when(signerConfig.getSerialNumber()).thenReturn("SN123");

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .assertNext(issuer -> {
                    assertEquals(DID_ELSI + "ORG-ID", issuer.getId());
                    assertEquals("ORG-ID", issuer.organizationIdentifier());
                    assertEquals("MyOrg", issuer.organization());
                    assertEquals("ES", issuer.country());
                    assertEquals("CN", issuer.commonName());
                    assertEquals("SN123", issuer.serialNumber());
                })
                .verifyComplete();

        verifyNoInteractions(qtspIssuerService);
        verifyNoInteractions(signingRecoveryService);
    }

    @Test
    void createSimpleIssuer_LocalServerSide_ReturnsFromDefaultConfig() {
        when(signingRuntimeProperties.getProvider()).thenReturn("in-memory");
        when(signerConfig.getOrganizationIdentifier()).thenReturn("ORG-ID");

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> assertEquals(DID_ELSI + "ORG-ID", simple.getId()))
                .verifyComplete();

        verifyNoInteractions(qtspIssuerService);
        verifyNoInteractions(signingRecoveryService);
    }

    @Test
    void createDetailedIssuer_Remote_SuccessPath() {
        when(signingRuntimeProperties.getProvider()).thenReturn("csc-sign-doc");
        when(qtspIssuerService.isServerMode()).thenReturn(false);

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

        verify(qtspIssuerService).isServerMode();
        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerService);
        verifyNoInteractions(signingRecoveryService);
    }

    @Test
    void createSimpleIssuer_Remote_SuccessPath() {
        when(signingRuntimeProperties.getProvider()).thenReturn("csc-sign-doc");
        when(qtspIssuerService.isServerMode()).thenReturn(false);

        DetailedIssuer detailed = DetailedIssuer.builder()
                .id("issuer-id")
                .build();

        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.just(detailed));

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> assertEquals("issuer-id", simple.getId()))
                .verifyComplete();

        verify(qtspIssuerService).isServerMode();
        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerService);
        verifyNoInteractions(signingRecoveryService);
    }

    @Test
    void createDetailedIssuer_Remote_Error_PropagatesError() {
        when(signingRuntimeProperties.getProvider()).thenReturn("csc-sign-doc");
        when(qtspIssuerService.isServerMode()).thenReturn(false);

        RemoteSignatureException ex = new RemoteSignatureException("boom");
        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(ex));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectErrorSatisfies(err -> assertEquals(ex, err))
                .verify();

        verify(qtspIssuerService).isServerMode();
        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerService);
        verifyNoInteractions(signingRecoveryService);
    }

    @Test
    void createDetailedIssuerAndNotifyOnError_Remote_Error_CompletesEmptyAndCallsPostRecover() {
        when(signingRuntimeProperties.getProvider()).thenReturn("csc-sign-doc");
        when(qtspIssuerService.isServerMode()).thenReturn(false);

        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new RemoteSignatureException("credentials mismatch")));

        when(signingRecoveryService.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .verifyComplete();

        verify(qtspIssuerService).isServerMode();
        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
        verify(signingRecoveryService).handlePostRecoverError(procedureId, "");
        verifyNoMoreInteractions(qtspIssuerService, signingRecoveryService);
    }

    @Test
    void createDetailedIssuerAndNotifyOnError_Remote_PostRecoverFails_PropagatesPostRecoverError() {
        when(signingRuntimeProperties.getProvider()).thenReturn("csc-sign-doc");
        when(qtspIssuerService.isServerMode()).thenReturn(false);

        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new RemoteSignatureException("boom")));

        RuntimeException postEx = new RuntimeException("post-recover failed");
        when(signingRecoveryService.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.error(postEx));

        StepVerifier.create(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .expectErrorSatisfies(err -> assertEquals(postEx, err))
                .verify();

        verify(qtspIssuerService).isServerMode();
        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
        verify(signingRecoveryService).handlePostRecoverError(procedureId, "");
        verifyNoMoreInteractions(qtspIssuerService, signingRecoveryService);
    }

    @Test
    void createDetailedIssuer_Remote_RecoverableErrors_ThenRetryExhausted() {
        when(signingRuntimeProperties.getProvider()).thenReturn("csc-sign-doc");
        when(qtspIssuerService.isServerMode()).thenReturn(false);

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

        verify(qtspIssuerService).isServerMode();
        verify(qtspIssuerService, times(1)).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerService);
        verifyNoInteractions(signingRecoveryService);
    }


    @Test
    void createDetailedIssuerAndNotifyOnError_Remote_RecoverableErrors_ThenPostRecoverCompletesEmpty() {
        when(signingRuntimeProperties.getProvider()).thenReturn("csc-sign-doc");
        when(qtspIssuerService.isServerMode()).thenReturn(false);

        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new TimeoutException("t1")));

        when(signingRecoveryService.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .verifyComplete();

        verify(qtspIssuerService).isServerMode();
        verify(qtspIssuerService, times(1)).resolveRemoteDetailedIssuer();
        verify(signingRecoveryService).handlePostRecoverError(procedureId, "");
        verifyNoMoreInteractions(qtspIssuerService, signingRecoveryService);
    }

    @Test
    void createSimpleIssuerAndNotifyOnError_Remote_Error_CompletesEmptyAndCallsPostRecover() {
        when(signingRuntimeProperties.getProvider()).thenReturn("csc-sign-doc");
        when(qtspIssuerService.isServerMode()).thenReturn(false);

        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new RemoteSignatureException("boom")));

        when(signingRecoveryService.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, ""))
                .verifyComplete();

        verify(qtspIssuerService).isServerMode();
        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
        verify(signingRecoveryService).handlePostRecoverError(procedureId, "");
        verifyNoMoreInteractions(qtspIssuerService, signingRecoveryService);
    }

    @Test
    void createSimpleIssuer_Remote_Success_MapsToSimpleIssuer() {
        when(signingRuntimeProperties.getProvider()).thenReturn("csc-sign-doc");
        when(qtspIssuerService.isServerMode()).thenReturn(false);

        DetailedIssuer detailed = DetailedIssuer.builder()
                .id("did:elsi:ABC")
                .build();

        when(qtspIssuerService.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.just(detailed));

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> {
                    assertEquals("did:elsi:ABC", simple.getId());
                })
                .verifyComplete();

        verify(qtspIssuerService).isServerMode();
        verify(qtspIssuerService).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerService);
        verifyNoInteractions(signingRecoveryService);
    }
}
