package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.util.JwtUtils;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListIndexNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListPublicBaseUrlNotResolvableException;
import es.in2.issuer.backend.statuslist.domain.factory.BitstringStatusListCredentialFactory;
import es.in2.issuer.backend.statuslist.domain.factory.TokenStatusListCredentialFactory;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusList;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PersistedStatusListPublicBaseUrlResolverTest {

    @Mock
    private StatusListIndexRepository statusListIndexRepository;

    @Mock
    private StatusListRepository statusListRepository;

    private final JwtUtils jwtUtils = new JwtUtils();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final BitstringStatusListCredentialFactory bitstringFactory = new BitstringStatusListCredentialFactory();
    private final TokenStatusListCredentialFactory tokenFactory = new TokenStatusListCredentialFactory();

    private PersistedStatusListPublicBaseUrlResolver resolver;

    private static final String ISSUANCE_ID = "6f1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
    private static final Long LIST_ID = 42L;
    private static final String BASE_URL = "https://issuer.example.com";

    @BeforeEach
    void setUp() {
        resolver = new PersistedStatusListPublicBaseUrlResolver(
                statusListIndexRepository, statusListRepository, jwtUtils, objectMapper);
    }

    private StatusListIndex indexFor(Long listId) {
        return new StatusListIndex(1L, listId, 0, UUID.fromString(ISSUANCE_ID), Instant.now());
    }

    /** Fabricates a compact-JWT-shaped string whose payload segment decodes to the given claims map. */
    private String fakeSignedJwt(Map<String, Object> claims) throws Exception {
        String json = objectMapper.writeValueAsString(claims);
        String payloadSegment = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
        return "header." + payloadSegment + ".signature";
    }

    @Test
    void resolve_bitstringVcFormat_derivesBaseUrlFromRealFactoryPayload() throws Exception {
        String listUrl = BASE_URL + "/w3c/v1/credentials/status/" + LIST_ID;
        Map<String, Object> payload = bitstringFactory.buildUnsigned(listUrl, "did:elsi:issuer", "revocation", "u1234");
        String signedCredential = fakeSignedJwt(payload);

        StatusList list = new StatusList(LIST_ID, "revocation", "bitstring_vc", "u1234", signedCredential, Instant.now(), Instant.now());

        when(statusListIndexRepository.findByIssuanceId(UUID.fromString(ISSUANCE_ID))).thenReturn(Mono.just(indexFor(LIST_ID)));
        when(statusListRepository.findById(LIST_ID)).thenReturn(Mono.just(list));

        StepVerifier.create(resolver.resolve(ISSUANCE_ID))
                .expectNext(BASE_URL)
                .verifyComplete();
    }

    @Test
    void resolve_tokenJwtFormat_derivesBaseUrlFromRealFactoryPayload() throws Exception {
        String listUrl = BASE_URL + "/token/v1/credentials/status/" + LIST_ID;
        Map<String, Object> payload = tokenFactory.buildUnsigned(listUrl, "did:elsi:issuer", "revocation", "u1234");
        String signedCredential = fakeSignedJwt(payload);

        StatusList list = new StatusList(LIST_ID, "revocation", "token_jwt", "u1234", signedCredential, Instant.now(), Instant.now());

        when(statusListIndexRepository.findByIssuanceId(UUID.fromString(ISSUANCE_ID))).thenReturn(Mono.just(indexFor(LIST_ID)));
        when(statusListRepository.findById(LIST_ID)).thenReturn(Mono.just(list));

        StepVerifier.create(resolver.resolve(ISSUANCE_ID))
                .expectNext(BASE_URL)
                .verifyComplete();
    }

    @Test
    void resolve_noAllocationForIssuance_throwsStatusListIndexNotFoundException() {
        when(statusListIndexRepository.findByIssuanceId(UUID.fromString(ISSUANCE_ID))).thenReturn(Mono.empty());

        StepVerifier.create(resolver.resolve(ISSUANCE_ID))
                .expectError(StatusListIndexNotFoundException.class)
                .verify();
    }

    @Test
    void resolve_listNotFound_throwsStatusListNotFoundException() {
        when(statusListIndexRepository.findByIssuanceId(UUID.fromString(ISSUANCE_ID))).thenReturn(Mono.just(indexFor(LIST_ID)));
        when(statusListRepository.findById(LIST_ID)).thenReturn(Mono.empty());

        StepVerifier.create(resolver.resolve(ISSUANCE_ID))
                .expectError(StatusListNotFoundException.class)
                .verify();
    }

    @Test
    void resolve_signedCredentialBlank_failsClosed() {
        StatusList list = new StatusList(LIST_ID, "revocation", "bitstring_vc", "u1234", "", Instant.now(), Instant.now());

        when(statusListIndexRepository.findByIssuanceId(UUID.fromString(ISSUANCE_ID))).thenReturn(Mono.just(indexFor(LIST_ID)));
        when(statusListRepository.findById(LIST_ID)).thenReturn(Mono.just(list));

        StepVerifier.create(resolver.resolve(ISSUANCE_ID))
                .expectError(StatusListPublicBaseUrlNotResolvableException.class)
                .verify();
    }

    @Test
    void resolve_claimSuffixDoesNotMatchExpectedListId_failsClosed() throws Exception {
        // 'id' points at a different listId than the row being resolved -> suffix mismatch.
        String listUrl = BASE_URL + "/w3c/v1/credentials/status/" + 999L;
        Map<String, Object> payload = bitstringFactory.buildUnsigned(listUrl, "did:elsi:issuer", "revocation", "u1234");
        String signedCredential = fakeSignedJwt(payload);

        StatusList list = new StatusList(LIST_ID, "revocation", "bitstring_vc", "u1234", signedCredential, Instant.now(), Instant.now());

        when(statusListIndexRepository.findByIssuanceId(UUID.fromString(ISSUANCE_ID))).thenReturn(Mono.just(indexFor(LIST_ID)));
        when(statusListRepository.findById(LIST_ID)).thenReturn(Mono.just(list));

        StepVerifier.create(resolver.resolve(ISSUANCE_ID))
                .expectError(StatusListPublicBaseUrlNotResolvableException.class)
                .verify();
    }

    @Test
    void resolve_malformedSignedCredential_failsClosed() {
        StatusList list = new StatusList(LIST_ID, "revocation", "bitstring_vc", "u1234", "not-a-jwt", Instant.now(), Instant.now());

        when(statusListIndexRepository.findByIssuanceId(UUID.fromString(ISSUANCE_ID))).thenReturn(Mono.just(indexFor(LIST_ID)));
        when(statusListRepository.findById(LIST_ID)).thenReturn(Mono.just(list));

        StepVerifier.create(resolver.resolve(ISSUANCE_ID))
                .expectError(StatusListPublicBaseUrlNotResolvableException.class)
                .verify();
    }
}
