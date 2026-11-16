package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Test double of {@link TenantSigningConfigService} that always answers the same configuration, or the
 * "no configuration" failure. It is built before the Mockito mocks of a test class exist, so it can be
 * handed to a {@code @Spy} field initializer.
 */
public final class FixedSigningConfigService implements TenantSigningConfigService {

    private final Mono<ActiveSigningConfig> answer;

    private FixedSigningConfigService(Mono<ActiveSigningConfig> answer) {
        this.answer = answer;
    }

    public static FixedSigningConfigService qtsp() {
        return new FixedSigningConfigService(Mono.just(ActiveSigningConfig.qtsp(new RemoteSignatureDto(
                "provider", "v2", "https://qtsp.example", "https://qtsp.example/auth", "signDoc", "credential",
                "password", null, null, null, null, null, null, null, null))));
    }

    public static FixedSigningConfigService ownKey() {
        return new FixedSigningConfigService(Mono.just(ActiveSigningConfig.ownKey(
                new OwnKeySigningConfig("kms-key", OwnKeySigningConfig.ES256, List.of("Y2VydA==")))));
    }

    public static FixedSigningConfigService noConfiguration() {
        return new FixedSigningConfigService(
                Mono.error(new SigningException(SigningFailureReason.NO_CONFIGURATION, "no config")));
    }

    @Override
    public Mono<ActiveSigningConfig> getActiveSigningConfig() {
        return answer;
    }

    @Override
    public Mono<ActiveSigningConfig> reloadActiveSigningConfig() {
        return answer;
    }
}
