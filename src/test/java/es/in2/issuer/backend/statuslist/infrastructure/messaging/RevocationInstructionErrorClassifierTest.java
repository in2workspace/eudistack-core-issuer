package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.statuslist.domain.exception.InvalidRevocationInstructionException;
import es.in2.issuer.backend.statuslist.domain.exception.OptimisticUpdateException;
import es.in2.issuer.backend.statuslist.domain.exception.RevocationInstructionInProgressException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListIndexNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListPublicBaseUrlNotResolvableException;
import es.in2.issuer.backend.statuslist.domain.exception.TenantBindingMismatchException;
import es.in2.issuer.backend.statuslist.domain.exception.UnknownTenantException;
import io.r2dbc.spi.R2dbcTimeoutException;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

class RevocationInstructionErrorClassifierTest {

    private final RevocationInstructionErrorClassifier classifier = new RevocationInstructionErrorClassifier();

    // ---------------------------------------------------------------- ES-01, ES-02, EC-07, AD-2: permanent

    @Test
    void isRetryable_invalidRevocationInstruction_isPermanent() {
        assertThat(classifier.isRetryable(new InvalidRevocationInstructionException("bad payload"))).isFalse();
    }

    @Test
    void isRetryable_unknownTenant_isPermanent() {
        assertThat(classifier.isRetryable(new UnknownTenantException("ghost-tenant"))).isFalse();
    }

    @Test
    void isRetryable_tenantBindingMismatch_isPermanent() {
        assertThat(classifier.isRetryable(new TenantBindingMismatchException("cgcom", "prh"))).isFalse();
    }

    @Test
    void isRetryable_issuanceNotFound_isPermanent() {
        assertThat(classifier.isRetryable(new IssuanceNotFoundException("no issuance"))).isFalse();
    }

    @Test
    void isRetryable_statusListIndexNotFound_isPermanent() {
        assertThat(classifier.isRetryable(new StatusListIndexNotFoundException("issuance-1"))).isFalse();
    }

    @Test
    void isRetryable_statusListNotFound_isPermanent() {
        assertThat(classifier.isRetryable(new StatusListNotFoundException(42L))).isFalse();
    }

    @Test
    void isRetryable_publicBaseUrlNotResolvable_isPermanent() {
        assertThat(classifier.isRetryable(new StatusListPublicBaseUrlNotResolvableException("cannot derive"))).isFalse();
    }

    // ---------------------------------------------------------------- ES-04, ES-05, EC-03: retryable

    @Test
    void isRetryable_remoteSignatureFailure_isRetryable() {
        assertThat(classifier.isRetryable(new RemoteSignatureException("QTSP down", new RuntimeException()))).isTrue();
    }

    @Test
    void isRetryable_r2dbcFailure_isRetryable() {
        assertThat(classifier.isRetryable(new R2dbcTimeoutException("db unavailable"))).isTrue();
    }

    @Test
    void isRetryable_optimisticUpdateResidual_isRetryable() {
        assertThat(classifier.isRetryable(new OptimisticUpdateException("lost the race"))).isTrue();
    }

    @Test
    void isRetryable_overlappingRedeliveryInProgress_isRetryable() {
        assertThat(classifier.isRetryable(new RevocationInstructionInProgressException("msg-1"))).isTrue();
    }

    @Test
    void isRetryable_processingTimeout_isRetryable() {
        assertThat(classifier.isRetryable(new TimeoutException("30s exceeded"))).isTrue();
    }

    // ---------------------------------------------------------------- default: unclassified -> retryable

    @Test
    void isRetryable_unclassifiedException_defaultsToRetryable() {
        assertThat(classifier.isRetryable(new RuntimeException("something unexpected"))).isTrue();
    }
}
