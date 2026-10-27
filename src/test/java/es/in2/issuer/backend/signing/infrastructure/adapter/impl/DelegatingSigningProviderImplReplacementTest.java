package es.in2.issuer.backend.signing.infrastructure.adapter.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import es.in2.issuer.backend.shared.domain.service.impl.TenantSigningConfigServiceImpl;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantSigningConfigRepository;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningProviderType;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.util.SigningConfigScope;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningAuditor;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningProviderResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An own key replaced while this instance still has the old configuration in cache (EUD-289 D-3, M4):
 * the old key is disabled, so signing with it fails with {@code KEY_UNUSABLE} and the configuration is
 * read again. With the real configuration service, this checks which certificate the payload and the
 * signature end up with, with and without a {@link SigningConfigScope}.
 */
@ExtendWith(MockitoExtension.class)
class DelegatingSigningProviderImplReplacementTest {

    private static final String OLD_KEY = "arn:aws:kms:eu-west-1:111122223333:key/old";
    private static final String NEW_KEY = "arn:aws:kms:eu-west-1:111122223333:key/new";

    @Mock
    private TenantSigningConfigRepository repository;
    @Mock
    private SigningProviderResolver signingProviderResolver;
    @Mock
    private SigningProvider kmsProvider;
    @Mock
    private SigningAuditor signingAuditor;

    private TenantSigningConfigServiceImpl configService;
    private DelegatingSigningProviderImpl signingProvider;

    /** A credential's issuer and its signature, each named by the key whose configuration produced it. */
    private record Issued(String payloadKey, String signatureKey) {}

    @BeforeEach
    void setUp() {
        // KMS signing disabled: the tag is not read, the provider is a mock here.
        @SuppressWarnings("unchecked")
        ObjectProvider<KmsSigningPort> noKms = mock(ObjectProvider.class);
        configService = new TenantSigningConfigServiceImpl(repository, new ObjectMapper(), Duration.ofMinutes(5), noKms);
        signingProvider = new DelegatingSigningProviderImpl(configService, signingProviderResolver, signingAuditor);

        // The cache holds the old key; the database already has its replacement.
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow(OLD_KEY)))
                .thenReturn(Mono.just(ownKeyRow(NEW_KEY)));
        when(signingProviderResolver.resolve(SigningProviderType.AWS_KMS)).thenReturn(kmsProvider);
        when(kmsProvider.sign(any())).thenAnswer(invocation -> {
            String keyRef = invocation.<SigningRequest>getArgument(0).ownKey().kmsKeyRef();
            return OLD_KEY.equals(keyRef)
                    ? Mono.error(new KmsSigningException(SigningFailureReason.KEY_UNUSABLE, "disabled"))
                    : Mono.just(new SigningResult(SigningType.JADES, keyRef));
        });
        StepVerifier.create(inTenant(configService.getActiveSigningConfig())).expectNextCount(1).verifyComplete();
    }

    private static TenantSigningConfig ownKeyRow(String keyRef) {
        return new TenantSigningConfig(UUID.randomUUID(), "aws-kms", null, null, null, null,
                "own_key", "active", null, null,
                keyRef, "ES256", "[\"MIIB-leaf\"]", null, null);
    }

    private static <T> Mono<T> inTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "cgcom"));
    }

    /** What an issuance does: bindIssuer reads the configuration, then the payload is signed. */
    private Mono<Issued> issue(AtomicInteger runs) {
        return configService.getActiveSigningConfig()
                .doOnNext(config -> runs.incrementAndGet())
                .flatMap(payloadConfig -> signingProvider.sign(SigningRequest.builder()
                                .type(SigningType.JADES)
                                .data("{}")
                                .context(new SigningContext("token", "issuance-1", null))
                                .build())
                        .map(signed -> new Issued(payloadConfig.ownKey().kmsKeyRef(), signed.data())));
    }

    @Test
    void withinScope_theIssuanceRunsAgainAndPayloadAndSignatureUseTheNewKey() {
        AtomicInteger runs = new AtomicInteger();

        StepVerifier.create(inTenant(SigningConfigScope.run(() -> issue(runs))))
                .expectNext(new Issued(NEW_KEY, NEW_KEY))
                .verifyComplete();
        assertThat(runs).hasValue(2);
    }

    @Test
    void withoutScope_theReloadSignsWithTheNewKeyAPayloadBuiltWithTheOldOne() {
        AtomicInteger runs = new AtomicInteger();

        StepVerifier.create(inTenant(issue(runs)))
                .expectNext(new Issued(OLD_KEY, NEW_KEY))
                .verifyComplete();
        assertThat(runs).hasValue(1);
    }
}
