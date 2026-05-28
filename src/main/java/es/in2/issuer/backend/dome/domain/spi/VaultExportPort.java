package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import reactor.core.publisher.Mono;

public interface VaultExportPort {

    Mono<byte[]> exportPrivateKey(LegacyKeyId keyId);
}

