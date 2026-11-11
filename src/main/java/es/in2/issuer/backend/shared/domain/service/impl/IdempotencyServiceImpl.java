package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyPolicy;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import es.in2.issuer.backend.shared.domain.service.IdempotencyService;
import es.in2.issuer.backend.shared.domain.spi.IdempotencyStore;
import es.in2.issuer.backend.shared.domain.util.Sha256;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Scopes the key to its requester, compares bodies by a digest of their canonical JSON and keeps the
 * successful responses in the shared {@link IdempotencyStore}.
 */
@Slf4j
@Service
public class IdempotencyServiceImpl implements IdempotencyService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String RESPONSE_KEY_LABEL = "eudistack-issuer-idempotent-response|";
    private static final String SCOPE_KEY_LABEL = "eudistack-issuer-idempotency-key|";
    private static final int COMPLETE_RETRIES = 2;
    private static final Duration COMPLETE_RETRY_BACKOFF = Duration.ofMillis(200);
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final byte SEALED_FORMAT_V1 = 1;
    /** Format byte and nonce, before the ciphertext and its tag. */
    private static final int SEALED_HEADER_BYTES = 1 + GCM_NONCE_BYTES;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final IdempotencyStore store;
    private final IdempotencyPolicy policy;
    private final Clock clock;
    private final ObjectMapper canonicalMapper;

    public IdempotencyServiceImpl(IdempotencyStore store, IdempotencyPolicy policy, Clock clock, ObjectMapper objectMapper) {
        this.store = store;
        this.policy = policy;
        this.clock = clock;
        // Trailing content must make the body "not JSON": otherwise "{}" and "{}x" would share a digest.
        this.canonicalMapper = objectMapper.copy()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
    }

    @Override
    public Mono<IdempotencyClaim> claim(Requester requester, String idempotencyKey, byte[] requestBody) {
        return Mono.defer(() -> {
            Instant now = clock.instant();
            String scopeKey = scopeKey(policy.serverSecret(), requester, idempotencyKey);
            byte[] responseKey = responseKey(policy.serverSecret(), requester, idempotencyKey);
            return store.claim(scopeKey, requestHash(requestBody), UUID.randomUUID().toString(),
                            now, now.plus(policy.lease()), now.plus(policy.retention()))
                    .map(claim -> switch (claim) {
                        case IdempotencyClaim.Acquired acquired -> acquired.withResponseKey(responseKey);
                        case IdempotencyClaim.Replay(StoredResponse sealed) -> new IdempotencyClaim.Replay(
                                open(sealed, responseKey, scopeKey));
                        default -> claim;
                    });
        });
    }

    @Override
    public Mono<Void> complete(IdempotencyClaim.Acquired claim, StoredResponse response) {
        return Mono.defer(() -> {
            byte[] responseKey = claim.responseKey();
            if (responseKey == null) {
                return Mono.error(new IllegalStateException("The claim has no response key"));
            }
            return store.complete(claim.scopeKey(), claim.ownerId(), seal(response, responseKey, claim.scopeKey()))
                    // A passing database failure must not leave a successful issuance without its response.
                    .retryWhen(Retry.backoff(COMPLETE_RETRIES, COMPLETE_RETRY_BACKOFF));
        });
    }

    @Override
    public Mono<Void> renew(IdempotencyClaim.Acquired claim) {
        return Mono.defer(() -> store.renew(claim.scopeKey(), claim.ownerId(), clock.instant().plus(policy.lease())));
    }

    @Override
    public Duration renewEvery() {
        return policy.renewEvery();
    }

    /**
     * The key that encrypts the kept response: HMAC-SHA256, keyed by the idempotency key, of the server secret
     * and the requester. Neither the idempotency key nor the secret is in the database, so the database alone
     * does not open the response, which with {@code direct} delivery is a signed attestation (the PRD of
     * EUD-254 does not keep it in clear).
     */
    static byte[] responseKey(String serverSecret, Requester requester, String idempotencyKey) {
        return hmac(idempotencyKey.getBytes(StandardCharsets.UTF_8),
                RESPONSE_KEY_LABEL + serverSecret + "|" + requester.idempotencyScope());
    }

    private static byte[] hmac(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }

    /** AES-256-GCM of the body, bound to its stored key: version byte, 12-byte nonce, ciphertext and tag. */
    static StoredResponse seal(StoredResponse response, byte[] responseKey, String scopeKey) {
        try {
            byte[] nonce = new byte[GCM_NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, responseKey, nonce, scopeKey);
            // Appended rather than sized by arithmetic on the body length (CodeQL java/uncontrolled-arithmetic).
            ByteArrayOutputStream sealed = new ByteArrayOutputStream();
            sealed.write(SEALED_FORMAT_V1);
            sealed.writeBytes(nonce);
            sealed.writeBytes(cipher.doFinal(response.body()));
            return new StoredResponse(response.status(), response.contentType(), response.location(), sealed.toByteArray());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not encrypt the idempotent response", e);
        }
    }

    static StoredResponse open(StoredResponse stored, byte[] responseKey, String scopeKey) {
        byte[] sealed = stored.body();
        if (sealed.length < SEALED_HEADER_BYTES || sealed[0] != SEALED_FORMAT_V1) {
            throw new IllegalStateException("The kept idempotent response has an unknown format");
        }
        try {
            byte[] nonce = Arrays.copyOfRange(sealed, 1, SEALED_HEADER_BYTES);
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, responseKey, nonce, scopeKey);
            byte[] body = cipher.doFinal(Arrays.copyOfRange(sealed, SEALED_HEADER_BYTES, sealed.length));
            return new StoredResponse(stored.status(), stored.contentType(), stored.location(), body);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not decrypt the kept idempotent response", e);
        }
    }

    private static Cipher cipher(int mode, byte[] key, byte[] nonce, String scopeKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(scopeKey.getBytes(StandardCharsets.UTF_8));
        return cipher;
    }

    @Override
    public Mono<Void> release(IdempotencyClaim.Acquired claim) {
        return store.release(claim.scopeKey(), claim.ownerId());
    }

    /**
     * The key within its caller, as a digest: the stored key names neither the caller nor the organization.
     * With a server secret it is an HMAC, so the database alone does not allow testing guessed keys.
     */
    static String scopeKey(String serverSecret, Requester requester, String idempotencyKey) {
        String scoped = requester.idempotencyScope() + "|" + idempotencyKey;
        return serverSecret.isEmpty()
                ? Sha256.hex(scoped)
                : HexFormat.of().formatHex(hmac(serverSecret.getBytes(StandardCharsets.UTF_8), SCOPE_KEY_LABEL + scoped));
    }

    /**
     * Digest of the body as canonical JSON (members sorted, no insignificant whitespace), so a retry that
     * serializes the same request differently is still the same body. A body that is not JSON is compared
     * byte for byte.
     */
    String requestHash(byte[] body) {
        if (body == null || body.length == 0) {
            return Sha256.hex(new byte[0]);
        }
        try {
            Object value = canonicalMapper.readValue(body, Object.class);
            return Sha256.hex(canonicalMapper.writeValueAsBytes(value));
        } catch (IOException _) {
            log.debug("Idempotent request body is not JSON, comparing it byte for byte");
            return Sha256.hex(body);
        }
    }
}
