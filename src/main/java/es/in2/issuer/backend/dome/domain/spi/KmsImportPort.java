package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.keymigration.EncryptedKeyEnvelope;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import reactor.core.publisher.Mono;

public interface KmsImportPort {

    Mono<KmsImportParameters> getParametersForImport(KmsAlias alias);

    Mono<Void> importKeyMaterial(KmsAlias alias, EncryptedKeyEnvelope envelope, KmsImportParameters params);

    Mono<String> sign(KmsAlias alias, byte[] data);

    Mono<KmsKeyDescription> describeKey(KmsAlias alias);

    Mono<KmsAlias> createKeyV2(String aliasName);

    Mono<Void> deleteImportedKeyMaterial(KmsAlias alias);

    record KmsImportParameters(String importToken, String publicKeyPem) {}

    record KmsKeyDescription(String keyId, String keyUsage, boolean enabled) {}
}
