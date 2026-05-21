package es.in2.issuer.backend.dome.infrastructure.adapter.keys;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;

/**
 * Resolves the public JWKS to be served at {@code /.well-known/jwks.json}.
 *
 * <p>When {@code planBEnabled=false} (default) it returns a single-key JWKSet backed by the
 * current AS {@link ECKey}.  When {@code planBEnabled=true} and the migration row is in status
 * {@code PLAN_B_REISSUE}, it returns a dual-key JWKSet (new key + legacy key) so that wallets
 * holding credentials signed with the old key can still verify them during the re-issuance
 * window (AC-06).
 *
 * <p>The result is cached with a configurable TTL (default 60 s) to avoid hitting the database
 * on every inbound JWKS request.  The endpoint is public and must never return HTTP 5xx — any
 * error falls back to the single-key JWKSet.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DomeJwkProvider {

    private static final String CACHE_KEY = "jwks";

    private final ECKey ecKey;
    private final KeyMigrationProperties migrationProperties;
    private final KmsKeyMigrationRepositoryPort migrationRepository;

    private Cache<String, JWKSet> jwksCache;

    @PostConstruct
    void initCache() {
        jwksCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(migrationProperties.cacheJwksTtlSeconds()))
                .maximumSize(1)
                .build();
    }

    /**
     * Returns the public JWKSet to publish.  Never emits an error signal.
     */
    public Mono<JWKSet> resolvePublicJwks() {
        JWKSet cached = jwksCache.getIfPresent(CACHE_KEY);
        if (cached != null) {
            return Mono.just(cached);
        }
        return buildJwks()
                .doOnNext(jwks -> jwksCache.put(CACHE_KEY, jwks))
                .onErrorResume(ex -> {
                    log.error("Failed to build JWKS, falling back to single-key set. error={} message={}",
                            ex.getClass().getName(), ex.getMessage(), ex);
                    return Mono.just(new JWKSet(ecKey.toPublicJWK()));
                });
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    private Mono<JWKSet> buildJwks() {
        if (!migrationProperties.planBEnabled()) {
            return Mono.just(new JWKSet(ecKey.toPublicJWK()));
        }

        String legacyId = migrationProperties.legacyKeyId();
        if (legacyId == null || legacyId.isBlank()) {
            log.warn("DOME key migration: planBEnabled=true but legacyKeyId is blank, serving single JWKS");
            return Mono.just(new JWKSet(ecKey.toPublicJWK()));
        }

        return migrationRepository.findByLegacyKeyId(new LegacyKeyId(legacyId))
                .flatMap(row -> {
                    if (!MigrationStatus.PLAN_B_REISSUE.name().equals(row.getMigrationStatus())) {
                        log.debug("DOME key migration: status={} is not PLAN_B_REISSUE, serving single JWKS",
                                row.getMigrationStatus());
                        return Mono.just(new JWKSet(ecKey.toPublicJWK()));
                    }
                    return buildDualJwks();
                })
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("DOME key migration: no kms_key_migration row found for legacyKeyId={}, "
                            + "serving single JWKS", legacyId);
                    return Mono.just(new JWKSet(ecKey.toPublicJWK()));
                }));
    }

    private Mono<JWKSet> buildDualJwks() {
        String legacyPubKeyHex = migrationProperties.legacyPublicKeyHex();
        if (legacyPubKeyHex == null || legacyPubKeyHex.isBlank()) {
            log.warn("DOME key migration: status=PLAN_B_REISSUE but legacyPublicKeyHex is blank, "
                    + "serving single JWKS");
            return Mono.just(new JWKSet(ecKey.toPublicJWK()));
        }
        return buildLegacyPublicKey(legacyPubKeyHex)
                .map(legacyKey -> new JWKSet(List.of(ecKey.toPublicJWK(), legacyKey)));
    }

    /**
     * Reconstructs an EC P-256 public {@link ECKey} from an uncompressed or compressed point
     * encoded as a hex string.  Runs on the bounded-elastic scheduler because it uses
     * blocking BouncyCastle operations.
     */
    private Mono<ECKey> buildLegacyPublicKey(String hexPublicKey) {
        return Mono.fromCallable(() -> {
            byte[] publicKeyBytes = HexFormat.of().parseHex(hexPublicKey);
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            org.bouncycastle.math.ec.ECPoint point = ecSpec.getCurve().decodePoint(publicKeyBytes);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, ecSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
            ECKey rawKey = new ECKey.Builder(Curve.P_256, publicKey).build();
            String thumbprint = rawKey.computeThumbprint().toString();
            log.debug("DOME key migration: legacy public key reconstructed with thumbprint={}", thumbprint);
            return new ECKey.Builder(rawKey).keyID("legacy-" + thumbprint).build();
        }).subscribeOn(Schedulers.boundedElastic());
    }
}

