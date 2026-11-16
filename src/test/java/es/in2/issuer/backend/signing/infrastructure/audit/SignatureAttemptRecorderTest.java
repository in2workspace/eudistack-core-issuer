package es.in2.issuer.backend.signing.infrastructure.audit;

import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.exception.RemoteSignatureUnauthorizedException;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.audit.AuditSource;
import es.in2.issuer.backend.shared.domain.service.FixedSigningConfigService;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents.SignedObject;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureAttemptRecorderTest {

    private static final String RESOURCE = "status-list:7";

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private final SignatureAttemptRecorder recorder = new SignatureAttemptRecorder(auditTrail, FixedSigningConfigService.qtsp());

    private static String signedJws() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString("cert".getBytes(StandardCharsets.UTF_8)) + "\"]}")
                        .getBytes(StandardCharsets.UTF_8));
        return header + ".payload.signature";
    }

    @Test
    void record_signatureWithCertificate_stagesSuccessOfTheSigningModuleForTheStatusList() {
        // Arrange
        Mono<String> signing = Mono.just(signedJws());

        // Act
        Mono<String> recorded = recorder.recordAttempt(RESOURCE, SignedObject.STATUS_LIST, signing);

        // Assert
        StepVerifier.create(recorded).expectNextCount(1).verifyComplete();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals(AuditSource.SIGNING, entry.source());
        assertEquals(RESOURCE, entry.resource());
        assertEquals("StatusList", entry.details().get("signed_object"));
        assertEquals("Qtsp", entry.details().get("modality"));
        assertEquals(1, entry.details().get("attempts"));
        assertTrue(entry.details().get("duration_ms") instanceof Long);
    }

    @Test
    void record_signatureWithoutJwsHeader_stagesNothingBecauseTheCatalogueRequiresTheCertificate() {
        // Arrange
        Mono<String> signing = Mono.just("base64-cose-bytes");

        // Act
        Mono<String> recorded = recorder.recordAttempt("issuance:1", SignedObject.ATTESTATION, signing);

        // Assert
        StepVerifier.create(recorded).expectNext("base64-cose-bytes").verifyComplete();
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void record_noSigningConfiguration_stagesNothingBecauseThereIsNoModalityToState() {
        // Arrange
        SignatureAttemptRecorder withoutConfiguration = new SignatureAttemptRecorder(auditTrail,
                FixedSigningConfigService.noConfiguration());
        Mono<String> signing = Mono.error(new SigningException(SigningFailureReason.NO_CONFIGURATION, "no config"));

        // Act
        Mono<String> recorded = withoutConfiguration.recordAttempt("issuance:1", SignedObject.ATTESTATION, signing);

        // Assert
        StepVerifier.create(recorded).expectError(SigningException.class).verify();
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void record_tenantSignsWithItsOwnKey_statesTheOwnKeyModality() {
        // Arrange
        SignatureAttemptRecorder ownKeyRecorder = new SignatureAttemptRecorder(auditTrail, FixedSigningConfigService.ownKey());

        // Act
        Mono<String> recorded = ownKeyRecorder.recordAttempt("issuance:1", SignedObject.ATTESTATION, Mono.just(signedJws()));

        // Assert
        StepVerifier.create(recorded).expectNextCount(1).verifyComplete();
        assertEquals("OwnKey", auditTrail.stagedInNewTransaction().getFirst().details().get("modality"));
    }

    @Test
    void record_ownKeySigningFails_statesTheOwnKeyModalityInTheFailure() {
        // Arrange
        SignatureAttemptRecorder ownKeyRecorder = new SignatureAttemptRecorder(auditTrail, FixedSigningConfigService.ownKey());
        Mono<String> signing = Mono.error(new RuntimeException("signing failed", new SocketTimeoutException("timeout")));

        // Act
        Mono<String> recorded = ownKeyRecorder.recordAttempt("issuance:1", SignedObject.ATTESTATION, signing);

        // Assert
        StepVerifier.create(recorded).expectError(RuntimeException.class).verify();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals("OwnKey", entry.details().get("modality"));
        assertEquals("ProviderUnavailable", entry.reason());
    }

    @Test
    void record_providerTimesOut_stagesFailureProviderUnavailable() {
        // Arrange
        Mono<String> signing = Mono.error(new RuntimeException("signing failed", new SocketTimeoutException("timeout")));

        // Act
        Mono<String> recorded = recorder.recordAttempt("issuance:1", SignedObject.ATTESTATION, signing);

        // Assert
        StepVerifier.create(recorded).expectError(RuntimeException.class).verify();
        assertEquals("ProviderUnavailable", auditTrail.stagedInNewTransaction().getFirst().reason());
    }

    @Test
    void record_providerRefusesTheCredentials_stagesFailureCredentialsRejected() {
        // Arrange
        Mono<String> signing = Mono.error(new RuntimeException("signing failed",
                new RemoteSignatureUnauthorizedException("Unauthorized: Invalid credentials")));

        // Act
        Mono<String> recorded = recorder.recordAttempt("issuance:1", SignedObject.ATTESTATION, signing);

        // Assert
        StepVerifier.create(recorded).expectError(RuntimeException.class).verify();
        assertEquals("CredentialsRejected", auditTrail.stagedInNewTransaction().getFirst().reason());
    }

    @Test
    void record_stagingFails_stillReturnsTheSignature() {
        // Arrange
        SignatureAttemptRecorder brokenRecorder = new SignatureAttemptRecorder(new RecordingAuditTrail().failingOnNewTransaction(),
                FixedSigningConfigService.qtsp());

        // Act
        Mono<String> recorded = brokenRecorder.recordAttempt(RESOURCE, SignedObject.STATUS_LIST, Mono.just(signedJws()));

        // Assert
        StepVerifier.create(recorded).expectNextCount(1).verifyComplete();
    }
}
