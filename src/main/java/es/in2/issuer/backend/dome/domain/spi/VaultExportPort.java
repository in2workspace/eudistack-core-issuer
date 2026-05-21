package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.keymigration.EncryptedKeyEnvelope;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import reactor.core.publisher.Mono;

public interface VaultExportPort {

    Mono<EncryptedKeyEnvelope> exportWrapped(LegacyKeyId keyId, String kmsWrappingKeyPublicKey);
}

