package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyPolicy;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.RequestControlSecrets;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.RequestControlSecrets.Secret;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import es.in2.issuer.backend.shared.domain.service.IdempotencyService;
import es.in2.issuer.backend.shared.domain.spi.IdempotencyStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.model.requestcontrol.RequestControlSecrets.IDEMPOTENCY_REQUEST_HASH;
import static es.in2.issuer.backend.shared.domain.model.requestcontrol.RequestControlSecrets.IDEMPOTENCY_RESPONSE_KEY;
import static es.in2.issuer.backend.shared.domain.model.requestcontrol.RequestControlSecrets.IDEMPOTENCY_SCOPE_KEY;

/**
 * Scopes the key to its requester, compares bodies by a digest of their canonical JSON and keeps the
 * successful responses in the shared {@link IdempotencyStore}, encrypted.
 *
 * <p>The stored key, the body digest and the key that encrypts the response are HMACs with keys derived
 * (HKDF-SHA256) from the idempotency secret ({@link RequestControlSecrets}), never from the client's input
 * alone. While the secret is rotated, a key not found with the current secret is looked up with the previous
 * one, so the responses of the last 24 hours are still returned and no retry creates another process.
 */
@Slf4j
@Service
public class IdempotencyServiceImpl implements IdempotencyService {

    private static final int COMPLETE_RETRIES = 2;
    private static final Duration COMPLETE_RETRY_BACKOFF = Duration.ofMillis(200);
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    /** Id of the secret (the format byte) and nonce, before the ciphertext and its tag. */
    private static final int SEALED_HEADER_BYTES = 1 + GCM_NONCE_BYTES;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final IdempotencyStore store;
    private final IdempotencyPolicy policy;
    private final RequestControlSecrets secrets;
    private final Clock clock;
    private final ObjectMapper canonicalMapper;

    public IdempotencyServiceImpl(IdempotencyStore store, IdempotencyPolicy policy, RequestControlSecrets secrets,
                                  Clock clock, ObjectMapper objectMapper) {
        this.store = store;
        this.policy = policy;
        this.secrets = secrets;
        this.clock = clock;
        // Trailing content must make the body "not JSON": otherwise "{}" and "{}x" would share a digest.
        this.canonicalMapper = objectMapper.copy()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
    }

    @Override
    public Mono<IdempotencyClaim> claim(Requester requester, String idempotencyKey, byte[] requestBody) {
        return Mono.defer(() -> {
            String scope = requester.idempotencyScope().orElseThrow(() -> new IllegalArgumentException(
                    "A requester the token does not name has no idempotency scope"));
            Instant now = clock.instant();
            byte[] canonicalBody = canonical(requestBody);
            Secret current = secrets.current();
            Mono<IdempotencyClaim> keptWithPrevious = secrets.previousSecret()
                    .map(previous -> {
                        String previousScopeKey = scopeKey(previous, scope, idempotencyKey);
                        return store.find(previousScopeKey, requestHash(previous, canonicalBody), now)
                                .map(found -> opened(found, previousScopeKey, scope, idempotencyKey));
                    })
                    .orElseGet(Mono::empty);
            return keptWithPrevious.switchIfEmpty(Mono.defer(() -> {
                String scopeKey = scopeKey(current, scope, idempotencyKey);
                return store.claim(scopeKey, requestHash(current, canonicalBody), UUID.randomUUID().toString(),
                                now, now.plus(policy.lease()), now.plus(policy.retention()))
                        .map(claim -> claim instanceof IdempotencyClaim.Acquired acquired
                                ? acquired.withResponseKey(responseKey(current, scope, idempotencyKey))
                                : opened(claim, scopeKey, scope, idempotencyKey));
            }));
        });
    }

    /** A replay with its response decrypted, with the secret its format byte names; any other claim as is. */
    private IdempotencyClaim opened(IdempotencyClaim claim, String scopeKey, String scope, String idempotencyKey) {
        if (!(claim instanceof IdempotencyClaim.Replay(StoredResponse sealed))) {
            return claim;
        }
        byte[] body = sealed.body();
        int secretId = body.length > 0 ? Byte.toUnsignedInt(body[0]) : 0;
        Secret secret = secrets.byId(secretId).orElseThrow(() -> new IllegalStateException(
                "The kept idempotent response was sealed with a secret that is no longer configured"));
        return new IdempotencyClaim.Replay(open(sealed, responseKey(secret, scope, idempotencyKey), scopeKey));
    }

    @Override
    public Mono<Void> complete(IdempotencyClaim.Acquired claim, StoredResponse response) {
        return Mono.defer(() -> {
            byte[] responseKey = claim.responseKey();
            if (responseKey == null) {
                return Mono.error(new IllegalStateException("The claim has no response key"));
            }
            StoredResponse sealed = seal(response, secrets.current().id(), responseKey, claim.scopeKey());
            return store.complete(claim.scopeKey(), claim.ownerId(), sealed)
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

    @Override
    public Mono<Void> release(IdempotencyClaim.Acquired claim) {
        return store.release(claim.scopeKey(), claim.ownerId());
    }

    /**
     * The key within its caller, as an HMAC: the stored key names neither the caller nor the organization,
     * and the database alone does not allow testing guessed keys.
     */
    static String scopeKey(Secret secret, String idempotencyScope, String idempotencyKey) {
        return secret.mac(IDEMPOTENCY_SCOPE_KEY, idempotencyScope + "|" + idempotencyKey);
    }

    /**
     * The key that encrypts the kept response: an HMAC of the caller and the idempotency key. Neither the
     * idempotency key nor the secret is in the database, so the database alone does not open the response,
     * which with {@code direct} delivery is a signed attestation (the PRD of EUD-254 does not keep it in clear).
     */
    static byte[] responseKey(Secret secret, String idempotencyScope, String idempotencyKey) {
        return secret.macBytes(IDEMPOTENCY_RESPONSE_KEY,
                (idempotencyScope + "|" + idempotencyKey).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * AES-256-GCM of the body, bound to its stored key and to the status, {@code Content-Type} and
     * {@code Location} kept in clear beside it: the id of the secret, a 12-byte nonce, the ciphertext and tag.
     */
    static StoredResponse seal(StoredResponse response, int secretId, byte[] responseKey, String scopeKey) {
        try {
            byte[] nonce = new byte[GCM_NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, responseKey, nonce, associatedData(scopeKey, response));
            // Appended rather than sized by arithmetic on the body length (CodeQL java/uncontrolled-arithmetic).
            ByteArrayOutputStream sealed = new ByteArrayOutputStream();
            sealed.write(secretId);
            sealed.writeBytes(nonce);
            sealed.writeBytes(cipher.doFinal(response.body()));
            return new StoredResponse(response.status(), response.contentType(), response.location(), sealed.toByteArray());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not encrypt the idempotent response", e);
        }
    }

    static StoredResponse open(StoredResponse stored, byte[] responseKey, String scopeKey) {
        byte[] sealed = stored.body();
        if (sealed.length < SEALED_HEADER_BYTES) {
            throw new IllegalStateException("The kept idempotent response has an unknown format");
        }
        try {
            byte[] nonce = Arrays.copyOfRange(sealed, 1, SEALED_HEADER_BYTES);
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, responseKey, nonce, associatedData(scopeKey, stored));
            byte[] body = cipher.doFinal(Arrays.copyOfRange(sealed, SEALED_HEADER_BYTES, sealed.length));
            return new StoredResponse(stored.status(), stored.contentType(), stored.location(), body);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not decrypt the kept idempotent response", e);
        }
    }

    /**
     * The stored key and the response fields kept in clear, each with its length (-1 when absent), so a
     * row whose status, {@code Content-Type} or {@code Location} was changed in the database is not opened.
     */
    static byte[] associatedData(String scopeKey, StoredResponse response) {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        for (String field : new String[] {scopeKey, Integer.toString(response.status()), response.contentType(),
                response.location()}) {
            byte[] bytes = field != null ? field.getBytes(StandardCharsets.UTF_8) : null;
            data.writeBytes(ByteBuffer.allocate(Integer.BYTES).putInt(bytes != null ? bytes.length : -1).array());
            if (bytes != null) {
                data.writeBytes(bytes);
            }
        }
        return data.toByteArray();
    }

    private static Cipher cipher(int mode, byte[] key, byte[] nonce, byte[] associatedData)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(associatedData);
        return cipher;
    }

    /** HMAC of the canonical body: the database alone does not allow testing guessed bodies. */
    static String requestHash(Secret secret, byte[] canonicalBody) {
        return secret.mac(IDEMPOTENCY_REQUEST_HASH, canonicalBody);
    }

    /**
     * The body as canonical JSON (members sorted, no insignificant whitespace), so a retry that serializes the
     * same request differently is still the same body. A body that is not JSON is compared byte for byte.
     */
    byte[] canonical(byte[] body) {
        if (body == null || body.length == 0) {
            return new byte[0];
        }
        try {
            Object value = canonicalMapper.readValue(body, Object.class);
            return canonicalMapper.writeValueAsBytes(value);
        } catch (IOException _) {
            log.debug("Idempotent request body is not JSON, comparing it byte for byte");
            return body;
        }
    }
}
