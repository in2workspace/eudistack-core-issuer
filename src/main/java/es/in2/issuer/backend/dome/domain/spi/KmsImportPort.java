package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.keymigration.EncryptedKeyEnvelope;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import reactor.core.publisher.Mono;

public interface KmsImportPort {

    /**
     * Retrieves the wrapping parameters needed to encrypt the key material before import.
     */
    Mono<KmsImportParameters> getParametersForImport(KmsAlias alias);

    /**
     * Imports the encrypted key material into the KMS under the given alias.
     */
    Mono<Void> importKeyMaterial(KmsAlias alias, EncryptedKeyEnvelope envelope, KmsImportParameters params);

    /**
     * Signs {@code data} with the key identified by {@code alias} and returns the signature as a base64 string.
     */
    Mono<String> sign(KmsAlias alias, byte[] data);

    /**
     * Retrieves key metadata for the alias.
     */
    Mono<KmsKeyDescription> describeKey(KmsAlias alias);

    /**
     * Creates a new CMK in the KMS and returns the canonical alias.
     */
    Mono<KmsAlias> createKeyV2(String aliasName);

    /**
     * Deletes the imported key material, leaving the key metadata but making the key non-functional.
     */
    Mono<Void> deleteImportedKeyMaterial(KmsAlias alias);

    record KmsImportParameters(String importToken, String publicKeyPem) {}

    record KmsKeyDescription(String keyId, String keyUsage, boolean enabled) {}
}

