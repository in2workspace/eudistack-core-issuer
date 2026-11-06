package es.in2.issuer.backend.signing.infrastructure.csc;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.audit.AuditSource;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import es.in2.issuer.backend.shared.infrastructure.audit.ExternalSystemAccessRecorder;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.ConnectException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CscPortRouterTest {

    @Mock
    private CscPort v2Adapter;

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private CscPortRouter router;

    @BeforeEach
    void setUp() {
        when(v2Adapter.supportedVersion()).thenReturn("v2");
        router = new CscPortRouter(List.of(v2Adapter), new ExternalSystemAccessRecorder(auditTrail));
    }

    private static RemoteSignatureDto config(String provider) {
        return new RemoteSignatureDto(provider, "v2", "https://qtsp.example.com/csc/v2", "https://qtsp.example.com/auth",
                "sign-hash", "credential-1", "secret", null, "client", "client-secret",
                null, null, null, null, null);
    }

    @Test
    void signHash_qtspAnswers_stagesASuccessAccessOfTheSigningModuleWithTheQtspHost() {
        // Arrange
        RemoteSignatureDto cfg = config("oauth2");
        when(v2Adapter.signHash(cfg, "token", "sad", "hash", "hashOid", "signOid")).thenReturn(Mono.just("signature"));

        // Act
        Mono<String> signed = router.signHash(cfg, "token", "sad", "hash", "hashOid", "signOid");

        // Assert
        StepVerifier.create(signed).expectNext("signature").verifyComplete();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals(AuditSource.SIGNING, entry.source());
        assertEquals("Qtsp", entry.details().get("system_type"));
        assertEquals("qtsp.example.com", entry.details().get("system"));
        assertEquals("signatures/signHash", entry.details().get("operation"));
        assertEquals("OAuthClientCredentials", entry.details().get("authentication_method"));
    }

    @Test
    void requestAccessToken_vintegrisProvider_reportsApiKeyAuthentication() {
        // Arrange
        RemoteSignatureDto cfg = config("vintegris");
        when(v2Adapter.requestAccessToken(cfg, "scope", false, "data")).thenReturn(Mono.just("access-token"));

        // Act
        Mono<String> token = router.requestAccessToken(cfg, "scope", false, "data");

        // Assert
        StepVerifier.create(token).expectNext("access-token").verifyComplete();
        assertEquals("ApiKey", auditTrail.stagedInNewTransaction().getFirst().details().get("authentication_method"));
        assertEquals("oauth2/token", auditTrail.stagedInNewTransaction().getFirst().details().get("operation"));
    }

    @Test
    void authorizeForHash_qtspUnreachable_stagesAFailureAndKeepsTheOriginalError() {
        // Arrange
        RemoteSignatureDto cfg = config("oauth2");
        ConnectException original = new ConnectException("refused");
        when(v2Adapter.authorizeForHash(cfg, "token", "hash", "hashOid")).thenReturn(Mono.error(original));

        // Act
        Mono<String> authorized = router.authorizeForHash(cfg, "token", "hash", "hashOid");

        // Assert
        StepVerifier.create(authorized).expectErrorMatches(error -> error == original).verify();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditResult.FAILURE, entry.result());
        assertEquals("Unreachable", entry.reason());
        assertEquals("credentials/authorize", entry.details().get("operation"));
    }

    @Test
    void signHash_unsupportedApiVersion_failsBeforeCallingTheQtspAndStagesNothing() {
        // Arrange
        RemoteSignatureDto cfg = new RemoteSignatureDto("oauth2", "v9", "https://qtsp.example.com", "https://qtsp.example.com/auth",
                "sign-hash", "credential-1", "secret", null, null, null, null, null, null, null, null);

        // Act & Assert
        assertThrows(IllegalArgumentException.class,
                () -> router.signHash(cfg, "token", "sad", "hash", "hashOid", "signOid"));
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void requestAccessToken_unusableQtspUrl_stillCallsTheQtspAndNamesTheSystemUnknown() {
        // Arrange
        RemoteSignatureDto cfg = new RemoteSignatureDto("oauth2", "v2", "not a url", "https://qtsp.example.com/auth",
                "sign-hash", "credential-1", "secret", null, "client", "client-secret",
                null, null, null, null, null);
        when(v2Adapter.requestAccessToken(cfg, "scope", false, null)).thenReturn(Mono.just("token"));

        // Act
        Mono<String> token = router.requestAccessToken(cfg, "scope", false, null);

        // Assert
        StepVerifier.create(token).expectNext("token").verifyComplete();
        assertEquals("unknown", auditTrail.stagedInNewTransaction().getFirst().details().get("system"));
    }
}
