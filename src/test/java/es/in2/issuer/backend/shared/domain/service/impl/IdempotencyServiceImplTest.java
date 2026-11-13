package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyPolicy;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.RequestControlSecrets;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.RequestControlSecrets.Secret;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import es.in2.issuer.backend.shared.domain.spi.IdempotencyStore;
import es.in2.issuer.backend.shared.domain.util.Sha256;
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
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IdempotencyServiceImplTest {

    private static final Secret SECRET = Secret.of(1, "server-secret-of-at-least-32-bytes");
    private static final Secret PREVIOUS = Secret.of(7, "previous-secret-of-at-least-32-bytes");
    private static final Instant NOW = Instant.parse("2026-11-10T10:00:00Z");
    private static final Requester SYSTEM = Requester.system("sandbox", "ORG-1", "m1");
    private static final String SCOPE = SYSTEM.idempotencyScope().orElseThrow();

    @Mock
    private IdempotencyStore store;

    private IdempotencyServiceImpl service;

    @BeforeEach
    void setUp() {
        service = service(new RequestControlSecrets(SECRET));
    }

    private IdempotencyServiceImpl service(RequestControlSecrets secrets) {
        return new IdempotencyServiceImpl(store, new IdempotencyPolicy(Duration.ofHours(24), Duration.ofMinutes(2)),
                secrets, Clock.fixed(NOW, ZoneOffset.UTC), new ObjectMapper());
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private String requestHash(String body) {
        return IdempotencyServiceImpl.requestHash(SECRET, service.canonical(body == null ? null : bytes(body)));
    }

    private static String scope(Requester requester) {
        return requester.idempotencyScope().orElseThrow();
    }

    @Test
    void requestHash_sameJsonSerializedDifferently_isTheSameBody() {
        String hash = requestHash("{\"a\":1,\"b\":{\"y\":2,\"x\":[1,2]}}");

        assertThat(requestHash(" { \"b\" : { \"x\" : [ 1, 2 ], \"y\" : 2 }, \"a\" : 1 } ")).isEqualTo(hash);
        assertThat(requestHash("{\"a\":1,\"b\":{\"y\":2,\"x\":[2,1]}}")).isNotEqualTo(hash);
    }

    @Test
    void requestHash_notJsonOrWithTrailingContent_isComparedByteForByte_andIsKeyedByTheSecret() {
        assertThat(requestHash("{}x")).isNotEqualTo(requestHash("{}"));
        assertThat(requestHash("plain")).isEqualTo(requestHash("plain"));
        assertThat(requestHash("")).isEqualTo(requestHash(null));
        assertThat(requestHash("{}")).hasSize(64).isNotEqualTo(Sha256.hex("{}"))
                .isNotEqualTo(IdempotencyServiceImpl.requestHash(PREVIOUS, bytes("{}")));
    }

    @Test
    void scopeKey_theSameKeyOfTwoRequestersNeverCollides_andNamesNobody() {
        String key = "retry-1";

        assertThat(IdempotencyServiceImpl.scopeKey(SECRET, SCOPE, key))
                .isNotEqualTo(IdempotencyServiceImpl.scopeKey(SECRET, scope(Requester.system("sandbox", "ORG-2", "m1")), key))
                .isNotEqualTo(IdempotencyServiceImpl.scopeKey(SECRET, scope(Requester.person("sandbox", "ORG-1", "m1")), key))
                .isNotEqualTo(IdempotencyServiceImpl.scopeKey(SECRET, scope(Requester.system("other", "ORG-1", "m1")), key))
                .hasSize(64)
                .doesNotContain("ORG-1");
    }

    @Test
    void scopeKey_dependsOnTheSecret_andOnTheSystemWithinItsOrganization() {
        String key = "order-1";

        assertThat(IdempotencyServiceImpl.scopeKey(SECRET, SCOPE, key))
                .isNotEqualTo(IdempotencyServiceImpl.scopeKey(PREVIOUS, SCOPE, key))
                .isNotEqualTo(IdempotencyServiceImpl.scopeKey(SECRET, scope(Requester.system("sandbox", "ORG-1", "m2")), key));
        assertThat(IdempotencyServiceImpl.responseKey(SECRET, SCOPE, key))
                .isNotEqualTo(IdempotencyServiceImpl.responseKey(PREVIOUS, SCOPE, key));
    }

    @Test
    void claim_ofACallerTheTokenDoesNotName_fails() {
        StepVerifier.create(service.claim(Requester.person("sandbox", "ORG-1", null), "k", bytes("{}")))
                .verifyError(IllegalArgumentException.class);
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
        AtomicInteger attempts = new AtomicInteger();
        when(store.complete(eq("scope"), eq("owner"), any())).thenReturn(Mono.defer(() ->
                attempts.incrementAndGet() == 1 ? Mono.error(new IllegalStateException("blip")) : Mono.empty()));

        StepVerifier.create(service.complete(new IdempotencyClaim.Acquired("scope", "owner",
                        IdempotencyServiceImpl.responseKey(SECRET, SCOPE, "k")),
                        new StoredResponse(200, null, null, bytes("{}"))))
                .verifyComplete();

        assertThat(attempts).hasValue(2);
    }

    @Test
    void claim_holdsTheKeyForTheLeaseAndKeepsItForTheRetention_withTheResponseKeyOfTheRequest() {
        when(store.claim(eq(IdempotencyServiceImpl.scopeKey(SECRET, SCOPE, "k")), eq(requestHash("{}")), anyString(),
                eq(NOW), eq(NOW.plus(Duration.ofMinutes(2))), eq(NOW.plus(Duration.ofHours(24)))))
                .thenReturn(Mono.just(new IdempotencyClaim.Acquired("scope", "owner")));

        StepVerifier.create(service.claim(SYSTEM, "k", bytes("{}")))
                .expectNext(new IdempotencyClaim.Acquired("scope", "owner",
                        IdempotencyServiceImpl.responseKey(SECRET, SCOPE, "k")))
                .verifyComplete();
        verify(store, never()).find(anyString(), anyString(), any());
    }

    @Test
    void complete_keepsTheResponseEncrypted_withTheIdOfTheSecret_andTheReplayOpensIt() {
        Requester requester = Requester.person("sandbox", "ORG-1", "p");
        String scopeKey = IdempotencyServiceImpl.scopeKey(SECRET, scope(requester), "k");
        byte[] responseKey = IdempotencyServiceImpl.responseKey(SECRET, scope(requester), "k");
        StoredResponse response = new StoredResponse(200, "application/json", "/x/1",
                bytes("{\"signed_credential\":\"eyJ\"}"));
        when(store.complete(eq(scopeKey), eq("owner"), any())).thenReturn(Mono.empty());

        StepVerifier.create(service.complete(new IdempotencyClaim.Acquired(scopeKey, "owner", responseKey), response))
                .verifyComplete();

        ArgumentCaptor<StoredResponse> stored = ArgumentCaptor.forClass(StoredResponse.class);
        verify(store).complete(eq(scopeKey), eq("owner"), stored.capture());
        assertThat(new String(stored.getValue().body(), StandardCharsets.ISO_8859_1)).doesNotContain("signed_credential");
        assertThat(stored.getValue().body()[0]).isEqualTo((byte) SECRET.id());
        assertThat(stored.getValue().status()).isEqualTo(200);
        assertThat(stored.getValue().location()).isEqualTo("/x/1");

        when(store.claim(anyString(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(Mono.just(new IdempotencyClaim.Replay(stored.getValue())));
        StepVerifier.create(service.claim(requester, "k", bytes("{}")))
                .expectNext(new IdempotencyClaim.Replay(response))
                .verifyComplete();
    }

    @Test
    void claim_whileTheSecretIsRotated_findsTheResponseKeptWithThePreviousOne() {
        StoredResponse response = new StoredResponse(201, "application/json", "/x/1", bytes("{\"ok\":true}"));
        String previousScopeKey = IdempotencyServiceImpl.scopeKey(PREVIOUS, SCOPE, "k");
        StoredResponse sealed = IdempotencyServiceImpl.seal(response, PREVIOUS.id(),
                IdempotencyServiceImpl.responseKey(PREVIOUS, SCOPE, "k"), previousScopeKey);
        when(store.find(previousScopeKey, IdempotencyServiceImpl.requestHash(PREVIOUS, bytes("{}")), NOW))
                .thenReturn(Mono.just(new IdempotencyClaim.Replay(sealed)));

        StepVerifier.create(service(new RequestControlSecrets(SECRET, PREVIOUS)).claim(SYSTEM, "k", bytes("{}")))
                .expectNext(new IdempotencyClaim.Replay(response))
                .verifyComplete();
        verify(store, never()).claim(anyString(), anyString(), anyString(), any(), any(), any());
    }

    @Test
    void claim_whileTheSecretIsRotated_aKeyNotKeptWithThePreviousOne_isClaimedWithTheCurrentOne() {
        when(store.find(anyString(), anyString(), any())).thenReturn(Mono.empty());
        when(store.claim(eq(IdempotencyServiceImpl.scopeKey(SECRET, SCOPE, "k")), anyString(), anyString(), any(),
                any(), any())).thenReturn(Mono.just(new IdempotencyClaim.Acquired("scope", "owner")));

        StepVerifier.create(service(new RequestControlSecrets(SECRET, PREVIOUS)).claim(SYSTEM, "k", bytes("{}")))
                .expectNext(new IdempotencyClaim.Acquired("scope", "owner",
                        IdempotencyServiceImpl.responseKey(SECRET, SCOPE, "k")))
                .verifyComplete();
    }

    @Test
    void claim_ofAResponseSealedWithASecretNoLongerConfigured_fails() {
        StoredResponse sealed = IdempotencyServiceImpl.seal(new StoredResponse(201, null, null, bytes("x")),
                PREVIOUS.id(), IdempotencyServiceImpl.responseKey(PREVIOUS, SCOPE, "k"), "scope");
        when(store.claim(anyString(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(Mono.just(new IdempotencyClaim.Replay(sealed)));

        StepVerifier.create(service.claim(SYSTEM, "k", bytes("{}"))).verifyError(IllegalStateException.class);
    }

    @Test
    void open_withAnotherIdempotencyKeyOrScope_fails() {
        StoredResponse sealed = IdempotencyServiceImpl.seal(new StoredResponse(201, null, null, bytes("body")),
                SECRET.id(), IdempotencyServiceImpl.responseKey(SECRET, SCOPE, "k"), "scope");

        byte[] otherKey = IdempotencyServiceImpl.responseKey(SECRET, SCOPE, "other");
        byte[] sameKey = IdempotencyServiceImpl.responseKey(SECRET, SCOPE, "k");

        assertThatThrownBy(() -> IdempotencyServiceImpl.open(sealed, otherKey, "scope"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> IdempotencyServiceImpl.open(sealed, sameKey, "other-scope"))
                .isInstanceOf(IllegalStateException.class);
        assertThat(IdempotencyServiceImpl.open(sealed, sameKey, "scope").body()).isEqualTo(bytes("body"));
    }

    @Test
    void open_aRowWhoseStatusContentTypeOrLocationWasChanged_fails() {
        byte[] key = IdempotencyServiceImpl.responseKey(SECRET, SCOPE, "k");
        StoredResponse sealed = IdempotencyServiceImpl.seal(
                new StoredResponse(201, "application/json", "/api/v1/issuances/1", bytes("body")), SECRET.id(), key, "scope");
        byte[] body = sealed.body();

        for (StoredResponse tampered : List.of(
                new StoredResponse(200, "application/json", "/api/v1/issuances/1", body),
                new StoredResponse(201, "text/html", "/api/v1/issuances/1", body),
                new StoredResponse(201, "application/json", "https://evil.example/", body),
                new StoredResponse(201, "application/json", null, body))) {
            assertThatThrownBy(() -> IdempotencyServiceImpl.open(tampered, key, "scope"))
                    .isInstanceOf(IllegalStateException.class);
        }
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
