package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyPolicy;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import es.in2.issuer.backend.shared.domain.spi.IdempotencyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IdempotencyServiceImplTest {

    private static final String SECRET = "server-secret";
    private static final Instant NOW = Instant.parse("2026-11-10T10:00:00Z");

    @Mock
    private IdempotencyStore store;

    private IdempotencyServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new IdempotencyServiceImpl(store, new IdempotencyPolicy(Duration.ofHours(24), Duration.ofMinutes(2), SECRET),
                Clock.fixed(NOW, ZoneOffset.UTC), new ObjectMapper());
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void requestHash_sameJsonSerializedDifferently_isTheSameBody() {
        String hash = service.requestHash(bytes("{\"a\":1,\"b\":{\"y\":2,\"x\":[1,2]}}"));

        assertThat(service.requestHash(bytes(" { \"b\" : { \"x\" : [ 1, 2 ], \"y\" : 2 }, \"a\" : 1 } "))).isEqualTo(hash);
        assertThat(service.requestHash(bytes("{\"a\":1,\"b\":{\"y\":2,\"x\":[2,1]}}"))).isNotEqualTo(hash);
    }

    @Test
    void requestHash_notJsonOrWithTrailingContent_isComparedByteForByte() {
        assertThat(service.requestHash(bytes("{}x"))).isNotEqualTo(service.requestHash(bytes("{}")));
        assertThat(service.requestHash(bytes("plain"))).isEqualTo(service.requestHash(bytes("plain")));
        assertThat(service.requestHash(new byte[0])).isEqualTo(service.requestHash(null));
    }

    @Test
    void scopeKey_theSameKeyOfTwoRequestersNeverCollides_andNamesNobody() {
        String key = "retry-1";

        assertThat(IdempotencyServiceImpl.scopeKey(SECRET, Requester.system("ORG-1"), key))
                .isNotEqualTo(IdempotencyServiceImpl.scopeKey(SECRET, Requester.system("ORG-2"), key))
                .isNotEqualTo(IdempotencyServiceImpl.scopeKey(SECRET, Requester.person("ORG-1", "p"), key))
                .hasSize(64)
                .doesNotContain("ORG-1");
    }

    @Test
    void scopeKey_dependsOnTheServerSecret_andOnTheSystemWithinItsOrganization() {
        String key = "order-1";

        assertThat(IdempotencyServiceImpl.scopeKey(SECRET, Requester.system("ORG-1", "m1"), key))
                .isNotEqualTo(IdempotencyServiceImpl.scopeKey("", Requester.system("ORG-1", "m1"), key))
                .isNotEqualTo(IdempotencyServiceImpl.scopeKey(SECRET, Requester.system("ORG-1", "m2"), key));
        assertThat(IdempotencyServiceImpl.responseKey(SECRET, Requester.system("ORG-1", "m1"), key))
                .isNotEqualTo(IdempotencyServiceImpl.responseKey("", Requester.system("ORG-1", "m1"), key));
    }

    @Test
    void renew_extendsTheLeaseOfTheRequestByOneLease() {
        when(store.renew("scope", "owner", NOW.plus(Duration.ofMinutes(2)))).thenReturn(Mono.empty());

        StepVerifier.create(service.renew(new IdempotencyClaim.Acquired("scope", "owner"))).verifyComplete();

        verify(store).renew("scope", "owner", NOW.plus(Duration.ofMinutes(2)));
        assertThat(service.renewEvery()).isEqualTo(Duration.ofMinutes(1));
    }

    @Test
    void complete_retriesAPassingFailureOfTheStore() {
        Requester requester = Requester.system("ORG-1");
        AtomicInteger attempts = new AtomicInteger();
        when(store.complete(eq("scope"), eq("owner"), any())).thenReturn(Mono.defer(() ->
                attempts.incrementAndGet() == 1 ? Mono.error(new IllegalStateException("blip")) : Mono.empty()));

        StepVerifier.create(service.complete(new IdempotencyClaim.Acquired("scope", "owner",
                        IdempotencyServiceImpl.responseKey(SECRET, requester, "k")),
                        new StoredResponse(200, null, null, bytes("{}"))))
                .verifyComplete();

        assertThat(attempts).hasValue(2);
    }

    @Test
    void claim_holdsTheKeyForTheLeaseAndKeepsItForTheRetention_withTheResponseKeyOfTheRequest() {
        Requester requester = Requester.system("ORG-1");
        when(store.claim(anyString(), anyString(), anyString(), eq(NOW), eq(NOW.plus(Duration.ofMinutes(2))),
                eq(NOW.plus(Duration.ofHours(24))))).thenReturn(Mono.just(new IdempotencyClaim.Acquired("scope", "owner")));

        StepVerifier.create(service.claim(requester, "k", bytes("{}")))
                .expectNext(new IdempotencyClaim.Acquired("scope", "owner",
                        IdempotencyServiceImpl.responseKey(SECRET, requester, "k")))
                .verifyComplete();
    }

    @Test
    void complete_keepsTheResponseEncrypted_andTheReplayOpensIt() {
        Requester requester = Requester.person("ORG-1", "p");
        String scopeKey = IdempotencyServiceImpl.scopeKey(SECRET, requester, "k");
        byte[] responseKey = IdempotencyServiceImpl.responseKey(SECRET, requester, "k");
        StoredResponse response = new StoredResponse(200, "application/json", "/x/1",
                bytes("{\"signed_credential\":\"eyJ\"}"));
        when(store.complete(eq(scopeKey), eq("owner"), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.complete(new IdempotencyClaim.Acquired(scopeKey, "owner", responseKey), response))
                .verifyComplete();

        ArgumentCaptor<StoredResponse> stored = ArgumentCaptor.forClass(StoredResponse.class);
        verify(store).complete(eq(scopeKey), eq("owner"), stored.capture());
        assertThat(new String(stored.getValue().body(), StandardCharsets.ISO_8859_1)).doesNotContain("signed_credential");
        assertThat(stored.getValue().status()).isEqualTo(200);
        assertThat(stored.getValue().location()).isEqualTo("/x/1");

        when(store.claim(anyString(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(Mono.just(new IdempotencyClaim.Replay(stored.getValue())));
        StepVerifier.create(service.claim(requester, "k", bytes("{}")))
                .expectNext(new IdempotencyClaim.Replay(response))
                .verifyComplete();
    }

    @Test
    void open_withAnotherIdempotencyKeyOrScope_fails() {
        Requester requester = Requester.system("ORG-1");
        StoredResponse sealed = IdempotencyServiceImpl.seal(new StoredResponse(201, null, null, bytes("body")),
                IdempotencyServiceImpl.responseKey(SECRET, requester, "k"), "scope");

        assertThatThrownBy(() -> IdempotencyServiceImpl.open(sealed,
                IdempotencyServiceImpl.responseKey(SECRET, requester, "other"), "scope"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> IdempotencyServiceImpl.open(sealed,
                IdempotencyServiceImpl.responseKey(SECRET, requester, "k"), "other-scope"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void complete_withoutResponseKey_failsInsteadOfKeepingItInClear() {
        StepVerifier.create(service.complete(new IdempotencyClaim.Acquired("scope", "owner"),
                        new StoredResponse(200, null, null, bytes("{}"))))
                .verifyError(IllegalStateException.class);
    }

    @Test
    void release_freesTheKeyOfTheRequest() {
        when(store.release("scope", "owner")).thenReturn(Mono.empty());

        StepVerifier.create(service.release(new IdempotencyClaim.Acquired("scope", "owner"))).verifyComplete();

        verify(store).release("scope", "owner");
    }
}
