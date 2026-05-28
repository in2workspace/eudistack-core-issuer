package es.in2.issuer.backend.dome.application.workflow.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import es.in2.issuer.backend.dome.application.service.KeyMigrationStateService;
import es.in2.issuer.backend.dome.domain.exception.HashMismatchException;
import es.in2.issuer.backend.dome.domain.model.keymigration.DomeSigningKey;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.DomeSigningKeyRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
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

@Service
@Profile("key-migration")
@RequiredArgsConstructor
@Slf4j
public class KeyMigrationWorkflowImpl
        implements es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow {

    private static final Marker AUDIT = MarkerFactory.getMarker("AUDIT_KEY_MIGRATION");

    private final VaultExportPort vaultExportPort;
    private final DomeSigningKeyRepositoryPort domeSigningKeyRepo;
    private final KeyMigrationStateService stateService;
    private final KeyMigrationProperties properties;

    @Override
    public Mono<Void> executePoc(String legacyKeyIdStr) {
        LegacyKeyId legacyKeyId = new LegacyKeyId(legacyKeyIdStr);
        log.info("executePoc: starting legacyKeyId={}", legacyKeyId.value());

        return vaultExportPort.exportPrivateKey(legacyKeyId)
                .flatMap(keyMaterial -> {
                    DomeSigningKey key = DomeSigningKey.builder()
                            .legacyKeyId(legacyKeyId.value())
                            .keyMaterial(keyMaterial)
                            .keyType("EC_P256")
                            .active(true)
                            .createdAt(Instant.now())
                            .build();
                    return domeSigningKeyRepo.save(key);
                })
                .flatMap(saved -> domeSigningKeyRepo.findActiveByLegacyKeyId(legacyKeyId.value()))
                .flatMap(retrieved -> validateKey(retrieved.getKeyMaterial()))
                .then(stateService.transitionTo(legacyKeyId, MigrationStatus.POC_OK))
                .doOnSuccess(entity -> log.info(AUDIT, "event=POC_OK legacyKeyId={}", legacyKeyId.value()))
                .then()
                .onErrorResume(ex -> stateService.transitionTo(legacyKeyId, MigrationStatus.FAILED)
                        .then(Mono.error(ex)));
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

