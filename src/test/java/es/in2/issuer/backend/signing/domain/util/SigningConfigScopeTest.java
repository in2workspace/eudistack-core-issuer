package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.signing.domain.exception.SigningConfigurationChangedException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class SigningConfigScopeTest {

    private static ActiveSigningConfig ownKey(String keyRef) {
        return ActiveSigningConfig.ownKey(new OwnKeySigningConfig(keyRef, "ES256", List.of("MIIB")));
    }

    private static Mono<SigningConfigScope.Pins> currentPins() {
        return Mono.deferContextual(ctx -> Mono.justOrEmpty(SigningConfigScope.current(ctx)));
    }

    @Test
    void outsideRun_thereAreNoPins() {
        StepVerifier.create(currentPins()).verifyComplete();
    }

    @Test
    void run_givesTheWorkPins() {
        StepVerifier.create(SigningConfigScope.run(SigningConfigScopeTest::currentPins))
                .assertNext(pins -> assertThat(pins).isNotNull())
                .verifyComplete();
    }

    @Test
    void run_configurationChanged_runsTheWorkOnceMoreWithNewPins() {
        List<SigningConfigScope.Pins> seen = new ArrayList<>();
        AtomicInteger runs = new AtomicInteger();

        Mono<String> result = SigningConfigScope.run(() -> currentPins().flatMap(pins -> {
            seen.add(pins);
            return runs.incrementAndGet() == 1
                    // Wrapped, as the issuance flows and the status list signer do.
                    ? Mono.error(new IllegalStateException("signing failed", new SigningConfigurationChangedException()))
                    : Mono.just("signed");
        }));

        StepVerifier.create(result).expectNext("signed").verifyComplete();
        assertThat(runs).hasValue(2);
        assertThat(seen.get(1)).isNotSameAs(seen.get(0));
    }

    @Test
    void run_configurationChangedTwice_failsWithKeyUnusable() {
        AtomicInteger runs = new AtomicInteger();

        Mono<String> result = SigningConfigScope.run(() -> {
            runs.incrementAndGet();
            return Mono.error(new SigningConfigurationChangedException());
        });

        StepVerifier.create(result)
                .expectErrorSatisfies(error -> assertThat(((SigningException) error).getReason())
                        .isEqualTo(SigningFailureReason.KEY_UNUSABLE))
                .verify();
        assertThat(runs).hasValue(2);
    }

    @Test
    void run_otherErrors_areNotRetried() {
        AtomicInteger runs = new AtomicInteger();

        Mono<String> result = SigningConfigScope.run(() -> {
            runs.incrementAndGet();
            return Mono.error(new SigningException(SigningFailureReason.KEY_UNUSABLE, "disabled"));
        });

        StepVerifier.create(result).expectError(SigningException.class).verify();
        assertThat(runs).hasValue(1);
    }

    @Test
    void nestedRun_joinsTheOuterPinsAndLeavesTheRetryToIt() {
        AtomicInteger outerRuns = new AtomicInteger();
        AtomicInteger innerRuns = new AtomicInteger();

        Mono<Boolean> result = SigningConfigScope.run(() -> currentPins().flatMap(outer -> {
            outerRuns.incrementAndGet();
            return SigningConfigScope.run(() -> currentPins().flatMap(inner -> {
                assertThat(inner).isSameAs(outer);
                return innerRuns.incrementAndGet() == 1
                        ? Mono.error(new SigningConfigurationChangedException())
                        : Mono.just(true);
            }));
        }));

        StepVerifier.create(result).expectNext(true).verifyComplete();
        assertThat(outerRuns).hasValue(2);
        assertThat(innerRuns).hasValue(2);
    }

    @Test
    void pins_keepTheFirstConfigurationOfEachTenant() {
        SigningConfigScope.Pins pins = new SigningConfigScope.Pins();
        ActiveSigningConfig first = ownKey("arn:first");

        assertThat(pins.pinIfAbsent("t1", first)).isSameAs(first);
        assertThat(pins.pinIfAbsent("t1", ownKey("arn:second"))).isSameAs(first);
        assertThat(pins.get("t1")).contains(first);
        assertThat(pins.get("t2")).isEmpty();
    }
}
