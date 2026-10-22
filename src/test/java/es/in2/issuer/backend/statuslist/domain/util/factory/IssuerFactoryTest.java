package es.in2.issuer.backend.statuslist.domain.util.factory;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.service.IssuerCertificateService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.TimeoutException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class IssuerFactoryTest {

    @Mock private IssuerCertificateService issuerCertificateService;
    @Mock private TenantSigningConfigService tenantSigningConfigService;
    @InjectMocks private IssuerFactory issuerFactory;

    private RemoteSignatureDto cfg;

    @BeforeEach
    void setUp() {
        cfg = new RemoteSignatureDto(
                "provider",
                "1",
                "",
                "",
                "sign-hash",
                "cred", "pwd",
                "PT10M",
                "client", "secret",
                "",
                "",
                "",
                "",
                ""
        );
    }

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

        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig.qtsp(cfg)));
        when(issuerCertificateService.resolveRemoteDetailedIssuer(cfg))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectNext(expected)
                .verifyComplete();

        verify(issuerCertificateService).resolveRemoteDetailedIssuer(cfg);
    }

    @Test
    void createSimpleIssuer_Remote_SuccessPath() {
        DetailedIssuer detailed = DetailedIssuer.builder()
                .id("issuer-id")
                .build();

        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig.qtsp(cfg)));
        when(issuerCertificateService.resolveRemoteDetailedIssuer(cfg))
                .thenReturn(Mono.just(detailed));

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> assertEquals("issuer-id", simple.getId()))
                .verifyComplete();

        verify(issuerCertificateService).resolveRemoteDetailedIssuer(cfg);
    }

    @Test
    void createDetailedIssuer_Remote_Error_PropagatesError() {
        RemoteSignatureException ex = new RemoteSignatureException("boom");
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig.qtsp(cfg)));
        when(issuerCertificateService.resolveRemoteDetailedIssuer(cfg))
                .thenReturn(Mono.error(ex));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectErrorSatisfies(err -> assertEquals(ex, err))
                .verify();

        verify(issuerCertificateService).resolveRemoteDetailedIssuer(cfg);
    }

    @Test
    void createDetailedIssuer_Remote_RecoverableErrors_ThenRetryExhausted() {
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig.qtsp(cfg)));
        when(issuerCertificateService.resolveRemoteDetailedIssuer(cfg))
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

        verify(issuerCertificateService, atLeast(1)).resolveRemoteDetailedIssuer(cfg);
    }

    @Test
    void createDetailedIssuer_failsIfTenantHasNoSigningConfig() {
        when(tenantSigningConfigService.getActiveSigningConfig()).thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectErrorSatisfies(err -> {
                    assertInstanceOf(SigningException.class, err);
                    assertTrue(err.getMessage().contains("No remote signature configuration"));
                    assertEquals(es.in2.issuer.backend.signing.domain.model.SigningFailureReason.NO_CONFIGURATION,
                            ((SigningException) err).getReason());
                })
                .verify();

        verify(issuerCertificateService, never()).resolveRemoteDetailedIssuer(any());
    }


    private static es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig ownKeyConfig() {
        return new es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig(
                "arn:aws:kms:eu-west-1:111122223333:key/k", "ES256", java.util.List.of("MIIB-leaf"),
                "a".repeat(64));
    }

    @Test
    void createDetailedIssuer_ownKeyModality_usesStoredCertificate_withoutCallingQtsp() {
        var ownKey = ownKeyConfig();
        DetailedIssuer expected = DetailedIssuer.builder().id("did:elsi:VATES-Q0000000X").build();
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig.ownKey(ownKey)));
        when(issuerCertificateService.resolveOwnKeyDetailedIssuer(ownKey)).thenReturn(Mono.just(expected));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectNext(expected)
                .verifyComplete();

        verify(issuerCertificateService).resolveOwnKeyDetailedIssuer(ownKey);
        verifyNoMoreInteractions(issuerCertificateService);
    }

    @Test
    void createSimpleIssuer_ownKeyModality_usesTheStoredCertificateIdentity() {
        var ownKey = ownKeyConfig();
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig.ownKey(ownKey)));
        when(issuerCertificateService.resolveOwnKeyDetailedIssuer(ownKey))
                .thenReturn(Mono.just(DetailedIssuer.builder().id("did:elsi:VATES-Q0000000X").build()));

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> assertEquals("did:elsi:VATES-Q0000000X", simple.getId()))
                .verifyComplete();
    }

    @Test
    void createDetailedIssuer_ownKeyModality_doesNotRetryAFailure() {
        var ownKey = ownKeyConfig();
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig.ownKey(ownKey)));
        when(issuerCertificateService.resolveOwnKeyDetailedIssuer(ownKey))
                .thenReturn(Mono.error(new TimeoutException("never retried")));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectError(TimeoutException.class)
                .verify();

        verify(issuerCertificateService, times(1)).resolveOwnKeyDetailedIssuer(ownKey);
    }
}
