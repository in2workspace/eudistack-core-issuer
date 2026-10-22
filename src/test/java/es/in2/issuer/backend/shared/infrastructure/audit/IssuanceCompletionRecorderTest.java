package es.in2.issuer.backend.shared.infrastructure.audit;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Completion;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Holder;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.WalletInteraction;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.service.IssuerCertificateService;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IssuanceCompletionRecorderTest {

    private static final String ISSUANCE_ID = "0b6f1d2e-aaaa-bbbb-cccc-111122223333";

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private final TenantSigningConfigService signingConfigService = mock(TenantSigningConfigService.class);
    private final IssuerCertificateService certificateService = mock(IssuerCertificateService.class);
    private final RemoteSignatureDto signingConfig = mock(RemoteSignatureDto.class);
    private final IssuanceCompletionRecorder recorder =
            new IssuanceCompletionRecorder(auditTrail, signingConfigService, certificateService);

    private static String signedJws() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString("cert".getBytes(StandardCharsets.UTF_8)) + "\"]}")
                        .getBytes(StandardCharsets.UTF_8));
        return header + ".payload.signature";
    }

    private static Completion completion(WalletInteraction walletInteraction) {
        return new Completion("learcredential.employee", "email", new Holder(null, "Jane Doe", "jane@example.com"),
                List.of("mandatee.firstName"), Instant.parse("2026-10-21T00:00:00Z"), Instant.parse("2027-10-21T00:00:00Z"),
                walletInteraction);
    }

    private void issuerIs(String organization, String organizationIdentifier) {
        when(signingConfigService.getRemoteSignature()).thenReturn(Mono.just(signingConfig));
        when(certificateService.resolveRemoteDetailedIssuer(signingConfig)).thenReturn(Mono.just(
                new DetailedIssuer("did:elsi:" + organizationIdentifier, organizationIdentifier, organization, "ES", "cn", "serial")));
    }

    @Test
    void record_deliveredThroughAWallet_stagesTheCompletionWithTheWalletExchange() {
        // Arrange
        issuerIs("ACME SL", "VATES-A1");

        // Act
        StepVerifier.create(recorder.recordCompletion(ISSUANCE_ID,
                completion(new WalletInteraction("oid4vci", "authorization_code", "dc+sd-jwt")), signedJws())).verifyComplete();

        // Assert
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditEventType.ISSUANCE_COMPLETED, entry.type());
        assertEquals("issuance:" + ISSUANCE_ID, entry.resource());
        assertEquals("ACME SL", entry.details().get("provider_legal_name"));
        assertEquals("VATES-A1", entry.details().get("provider_registration_id"));
        assertEquals(true, entry.details().get("accepted_by_holder"));
        assertTrue(entry.details().containsKey("wallet_interaction"));
    }

    @Test
    void record_deliveredDirectly_omitsTheWalletExchange() {
        // Arrange
        issuerIs("ACME SL", "VATES-A1");

        // Act
        StepVerifier.create(recorder.recordCompletion(ISSUANCE_ID, completion(null), signedJws())).verifyComplete();

        // Assert
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertFalse(entry.details().containsKey("wallet_interaction"));
        assertFalse(entry.details().containsKey("accepted_by_holder"));
    }

    @Test
    void record_keepsOnlyFingerprintsOfTheCertificateAndTheAttestation() {
        // Arrange
        issuerIs("ACME SL", "VATES-A1");
        String signed = signedJws();

        // Act
        StepVerifier.create(recorder.recordCompletion(ISSUANCE_ID, completion(null), signed)).verifyComplete();

        // Assert
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertTrue(entry.details().get("signing_certificate").toString().startsWith("sha256:"));
        assertTrue(entry.details().get("attestation_hash").toString().startsWith("sha256:"));
        assertFalse(entry.details().toString().contains(signed));
    }

    @Test
    void record_signatureWithoutAJwsHeader_stagesNothing() {
        // Arrange & Act
        StepVerifier.create(recorder.recordCompletion(ISSUANCE_ID, completion(null), "base45-cose-value")).verifyComplete();

        // Assert
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void record_issuerWithoutOrganization_stagesNothing() {
        // Arrange
        issuerIs(null, null);

        // Act
        StepVerifier.create(recorder.recordCompletion(ISSUANCE_ID, completion(null), signedJws())).verifyComplete();

        // Assert
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void record_issuerLookupFails_completesWithoutStagingAnything() {
        // Arrange
        when(signingConfigService.getRemoteSignature()).thenReturn(Mono.just(signingConfig));
        when(certificateService.resolveRemoteDetailedIssuer(signingConfig)).thenReturn(Mono.error(new IllegalStateException("qtsp down")));

        // Act
        StepVerifier.create(recorder.recordCompletion(ISSUANCE_ID, completion(null), signedJws())).verifyComplete();

        // Assert
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void record_auditChannelDown_stillCompletes() {
        // Arrange
        issuerIs("ACME SL", "VATES-A1");
        IssuanceCompletionRecorder brokenRecorder =
                new IssuanceCompletionRecorder(new RecordingAuditTrail().failingOnNewTransaction(), signingConfigService, certificateService);

        // Act & Assert
        StepVerifier.create(brokenRecorder.recordCompletion(ISSUANCE_ID, completion(null), signedJws())).verifyComplete();
    }
}
