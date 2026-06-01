package es.in2.issuer.backend.dome.application.workflow.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import es.in2.issuer.backend.dome.application.service.KeyMigrationStateService;
import es.in2.issuer.backend.dome.domain.exception.ConflictingMigrationStateException;
import es.in2.issuer.backend.dome.domain.exception.HashMismatchException;
import es.in2.issuer.backend.dome.domain.model.keymigration.DomeSigningKey;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.DomeSigningKeyRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Service
@Profile("key-migration")
@RequiredArgsConstructor
@Slf4j
public class KeyMigrationWorkflowImpl
        implements es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow {

    private static final Marker AUDIT = MarkerFactory.getMarker("AUDIT_KEY_MIGRATION");
    private static final String TENANT_REQUIRED_MSG =
            "Tenant domain must be present in Reactor context for key migration operations";

    private final VaultExportPort vaultExportPort;
    private final DomeSigningKeyRepositoryPort domeSigningKeyRepo;
    private final KeyMigrationStateService stateService;

    @Override
    public Mono<Void> executePoc(String legacyKeyIdStr) {
        LegacyKeyId legacyKeyId = new LegacyKeyId(legacyKeyIdStr);
        log.info("executePoc: starting legacyKeyId={}", legacyKeyId.value());

        return Mono.deferContextual(ctx -> {
            String tenantId = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            if (tenantId.isBlank()) {
                return Mono.error(new IllegalStateException(TENANT_REQUIRED_MSG));
            }

            // Reject terminal states before any side-effectful work to give a
            // clear, actionable error instead of a DB-constraint/state-machine cascade.
            return stateService.currentStatus(legacyKeyIdStr)
                    .defaultIfEmpty(MigrationStatus.PENDING)
                    .flatMap(current -> {
                        if (current == MigrationStatus.MIGRATED || current == MigrationStatus.ROLLED_BACK) {
                            return Mono.<Void>error(new ConflictingMigrationStateException(
                                    "PoC cannot be re-executed from terminal state: " + current));
                        }
                        // Idempotent: reuse existing active key if the PoC was already run,
                        // avoiding a unique-constraint violation on re-runs.
                        return domeSigningKeyRepo.findActiveByLegacyKeyId(legacyKeyId.value())
                                .switchIfEmpty(
                                        vaultExportPort.exportPrivateKey(legacyKeyId)
                                                .flatMap(keyMaterial -> computePublicJwk(keyMaterial)
                                                        .map(publicJwk -> DomeSigningKey.builder()
                                                                .keyId(UUID.randomUUID().toString())
                                                                .holderId(legacyKeyId.value())
                                                                .credentialId(legacyKeyId.value())
                                                                .tenantId(tenantId)
                                                                .privateKey(keyMaterial)
                                                                .publicJwk(publicJwk)
                                                                .algorithm("ES256")
                                                                .format("dc+sd-jwt")
                                                                .createdAt(Instant.now())
                                                                .build()))
                                                .flatMap(domeSigningKeyRepo::save))
                                .flatMap(retrieved -> validateKey(retrieved.getPrivateKey()))
                                .then(stateService.transitionTo(legacyKeyId, MigrationStatus.POC_OK))
                                .doOnSuccess(entity -> log.info(AUDIT, "event=POC_OK legacyKeyId={}", legacyKeyId.value()))
                                .then();
                    })
                    .onErrorResume(ex -> {
                        // ConflictingMigrationStateException means we deliberately rejected
                        // the operation — do NOT attempt to record a FAILED transition.
                        if (ex instanceof ConflictingMigrationStateException) {
                            return Mono.error(ex);
                        }
                        return stateService.transitionTo(legacyKeyId, MigrationStatus.FAILED)
                                .onErrorResume(transitionEx -> {
                                    // The DB may itself be down; log but never swallow the original error.
                                    log.warn("Failed to record FAILED state for legacyKeyId={}: {}",
                                            legacyKeyId.value(), transitionEx.getMessage());
                                    return Mono.empty();
                                })
                                .then(Mono.error(ex));
                    });
        });
    }

    @Override
    public Mono<Void> executeMigration(String legacyKeyIdStr) {
        LegacyKeyId legacyKeyId = new LegacyKeyId(legacyKeyIdStr);

        return Mono.deferContextual(ctx -> {
            String tenantId = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            if (tenantId.isBlank()) {
                return Mono.error(new IllegalStateException(TENANT_REQUIRED_MSG));
            }

            return stateService.currentStatus(legacyKeyIdStr)
                    .switchIfEmpty(Mono.error(new ConflictingMigrationStateException(
                            "Migration can only be executed from POC_OK state. " +
                            "No migration record found for legacyKeyId: " + legacyKeyIdStr)))
                    .flatMap(current -> {
                        if (current != MigrationStatus.POC_OK) {
                            return Mono.<DomeSigningKey>error(new ConflictingMigrationStateException(
                                    "Migration can only be executed from POC_OK state. Current state: " + current));
                        }
                        return domeSigningKeyRepo.findActiveByLegacyKeyId(legacyKeyIdStr)
                                .switchIfEmpty(Mono.error(new IllegalStateException(
                                        "No active signing key found for legacyKeyId: " + legacyKeyIdStr)));
                    })
                    .then(stateService.transitionTo(legacyKeyId, MigrationStatus.MIGRATED))
                    .doOnSuccess(entity -> log.info(AUDIT, "event=MIGRATED legacyKeyId={}", legacyKeyId.value()))
                    .then();
        });
    }

    @Override
    public Mono<Void> executeRollback(String legacyKeyIdStr) {
        LegacyKeyId legacyKeyId = new LegacyKeyId(legacyKeyIdStr);

        return Mono.deferContextual(ctx -> {
            String tenantId = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            if (tenantId.isBlank()) {
                return Mono.error(new IllegalStateException(TENANT_REQUIRED_MSG));
            }

            return stateService.currentStatus(legacyKeyIdStr)
                    .switchIfEmpty(Mono.error(new ConflictingMigrationStateException(
                            "Cannot roll back: no migration record found for legacyKeyId: " + legacyKeyIdStr)))
                    .flatMap(current -> {
                        if (current == MigrationStatus.MIGRATED) {
                            return Mono.<MigrationStatus>error(new ConflictingMigrationStateException(
                                    "Cannot roll back a completed migration. State: MIGRATED"));
                        }
                        if (current != MigrationStatus.POC_OK) {
                            return Mono.<MigrationStatus>error(new ConflictingMigrationStateException(
                                    "Migration can only be executed from POC_OK state. Current state: " + current));
                        }
                        return Mono.just(current);
                    })
                    .then(domeSigningKeyRepo.deactivateByLegacyKeyId(legacyKeyIdStr))
                    .then(stateService.transitionTo(legacyKeyId, MigrationStatus.ROLLED_BACK))
                    .doOnSuccess(entity -> log.info(AUDIT, "event=ROLLED_BACK legacyKeyId={}", legacyKeyId.value()))
                    .then();
        });
    }

    private Mono<String> computePublicJwk(byte[] keyMaterial) {
        return Mono.fromCallable(() -> {
                    KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
                    ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(
                            new PKCS8EncodedKeySpec(keyMaterial));

                    BigInteger s = privateKey.getS();
                    ECParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
                    org.bouncycastle.math.ec.ECPoint q = bcSpec.getG().multiply(s);
                    ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, bcSpec);
                    ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec);

                    return new ECKey.Builder(Curve.P_256, publicKey).build().toJSONString();
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Void> validateKey(byte[] keyMaterial) {
        return Mono.fromCallable(() -> {
                    KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
                    ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(
                            new PKCS8EncodedKeySpec(keyMaterial));

                    BigInteger s = privateKey.getS();
                    ECParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
                    org.bouncycastle.math.ec.ECPoint q = bcSpec.getG().multiply(s);
                    ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, bcSpec);
                    ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec);

                    JWSHeader header = new JWSHeader(JWSAlgorithm.ES256);
                    JWSObject jwsObject = new JWSObject(header, new Payload("dome-poc-test"));
                    jwsObject.sign(new ECDSASigner(privateKey));

                    boolean valid = jwsObject.verify(new ECDSAVerifier(publicKey));
                    if (!valid) {
                        throw new HashMismatchException("PoC validation failed: signature did not verify");
                    }
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }
}
