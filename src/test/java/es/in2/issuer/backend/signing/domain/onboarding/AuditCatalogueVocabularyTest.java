package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Operation;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Result;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The reasons the tool can emit for {@code SigningConfigurationChanged} are the ones the audit catalogue defines: the
 * audit API rejects an event whose reason is outside the vocabulary of its type.
 */
class AuditCatalogueVocabularyTest {

    /**
     * Copied from {@code docs/features/EUD-244-api-auditoria/annex/catalogo-eventos.yaml} of eudistack-platform-dev,
     * catalog_version 2.2.0, event {@code SigningConfigurationChanged}: {@code reasons} with the result each one has.
     * A change of the catalogue must be reflected here and in {@link RejectionReason}.
     */
    private static final Map<String, String> CATALOGUE_REASONS = Map.of(
            "PolicyDenied", "Denied",
            "InvalidKey", "Denied",
            "InvalidCertificate", "Denied",
            "KeyInUse", "Denied",
            "ProviderUnavailable", "Failure");

    @Test
    void everyReasonTheToolCanEmit_isInTheCatalogueVocabularyWithItsResult() {
        Map<String, String> emitted = new java.util.HashMap<>();
        Arrays.stream(RejectionReason.values())
                .forEach(reason -> emitted.put(reason.catalogName(), reason.result().catalogName()));

        assertThat(emitted.entrySet()).isSubsetOf(CATALOGUE_REASONS.entrySet());
    }

    @Test
    void aFailureEvent_carriesTheOnlyFailureReasonOfTheCatalogue() {
        var event = SigningConfigurationChanged.retire("cgcom", Result.FAILURE, RejectionReason.PROVIDER_UNAVAILABLE,
                "arn", Duration.ZERO, Instant.EPOCH, "id");

        assertThat(event.reason().catalogName()).isEqualTo("ProviderUnavailable");
    }

    @Test
    void anEventWithAReasonOfAnotherResult_isRefused() {
        assertThatThrownBy(() -> SigningConfigurationChanged.retire("cgcom", Result.FAILURE, RejectionReason.KEY_IN_USE,
                "arn", Duration.ZERO, Instant.EPOCH, "id")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SigningConfigurationChanged.retire("cgcom", Result.DENIED, null, "arn",
                Duration.ZERO, Instant.EPOCH, "id")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SigningConfigurationChanged("cgcom", Operation.CREATE, Result.SUCCESS,
                RejectionReason.KEY_IN_USE, null, null, null, "arn", Duration.ZERO, Instant.EPOCH, null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
