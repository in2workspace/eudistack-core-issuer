package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeSigningKey;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.time.Instant;

interface DomeSigningKeyR2dbcRepo extends ReactiveCrudRepository<DomeSigningKey, String> {

    // RETURNING casts public_jwk to text so the R2DBC driver maps it to String without a JSONB converter
    @Query("INSERT INTO holder_key " +
            "(key_id, holder_id, credential_id, tenant_id, private_key, public_jwk, algorithm, format, created_at) " +
            "VALUES (:keyId, :holderId, :credentialId, :tenantId, :privateKey, :publicJwk::jsonb, :algorithm, :format, :createdAt) " +
            "RETURNING key_id, holder_id, credential_id, tenant_id, private_key, " +
            "public_jwk::text AS public_jwk, algorithm, format, created_at, revoked_at")
    Mono<DomeSigningKey> insertKey(String keyId, String holderId, String credentialId, String tenantId,
                                    byte[] privateKey, String publicJwk, String algorithm, String format,
                                    Instant createdAt);

    // SELECT casts public_jwk to text for the same reason
    @Query("SELECT key_id, holder_id, credential_id, tenant_id, private_key, " +
            "public_jwk::text AS public_jwk, algorithm, format, created_at, revoked_at " +
            "FROM holder_key WHERE holder_id = :legacyKeyId AND revoked_at IS NULL LIMIT 1")
    Mono<DomeSigningKey> findActiveByLegacyKeyId(String legacyKeyId);

    @Query("UPDATE holder_key SET revoked_at = now() WHERE holder_id = :legacyKeyId AND revoked_at IS NULL")
    Mono<Void> deactivateByLegacyKeyId(String legacyKeyId);
}
