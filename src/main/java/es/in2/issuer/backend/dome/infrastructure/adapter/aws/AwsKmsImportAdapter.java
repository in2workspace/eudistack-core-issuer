package es.in2.issuer.backend.dome.infrastructure.adapter.aws;

import es.in2.issuer.backend.dome.domain.exception.KmsAliasNotProvisionedException;
import es.in2.issuer.backend.dome.domain.exception.PostImportValidationFailedException;
import es.in2.issuer.backend.dome.domain.model.keymigration.EncryptedKeyEnvelope;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.spi.KmsImportPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.AlgorithmSpec;
import software.amazon.awssdk.services.kms.model.CreateAliasRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.DeleteImportedKeyMaterialRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.GetParametersForImportRequest;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.NotFoundException;
import software.amazon.awssdk.services.kms.model.OriginType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.WrappingKeySpec;

import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeoutException;

@Slf4j
@Lazy
@Profile("key-migration")
@Component
@RequiredArgsConstructor
public class AwsKmsImportAdapter implements KmsImportPort {

    private final KmsAsyncClient kmsClient;

    @Override
    public Mono<KmsImportParameters> getParametersForImport(KmsAlias alias) {
        log.debug("Requesting import parameters from KMS for alias");
        GetParametersForImportRequest request = GetParametersForImportRequest.builder()
                .keyId(alias.value())
                .wrappingAlgorithm(AlgorithmSpec.RSAES_OAEP_SHA_256)
                .wrappingKeySpec(WrappingKeySpec.RSA_2048)
                .build();
        return Mono.fromCompletionStage(kmsClient.getParametersForImport(request))
                .map(response -> {
                    String importToken = Base64.getEncoder()
                            .encodeToString(response.importToken().asByteArray());
                    String publicKeyPem = toPem(response.publicKey().asByteArray());
                    log.debug("Received import parameters from KMS");
                    return new KmsImportParameters(importToken, publicKeyPem);
                });
    }

    @Override
    public Mono<Void> importKeyMaterial(KmsAlias alias, EncryptedKeyEnvelope envelope,
                                        KmsImportParameters params) {
        log.debug("Importing key material into KMS for alias");
        byte[] tokenBytes = Base64.getDecoder().decode(params.importToken());
        ImportKeyMaterialRequest request = ImportKeyMaterialRequest.builder()
                .keyId(alias.value())
                .encryptedKeyMaterial(SdkBytes.fromByteArray(envelope.ciphertext()))
                .importToken(SdkBytes.fromByteArray(tokenBytes))
                .build();
        return Mono.fromCompletionStage(kmsClient.importKeyMaterial(request))
                .doFinally(signal -> {
                    Arrays.fill(envelope.ciphertext(), (byte) 0);
                    Arrays.fill(tokenBytes, (byte) 0);
                })
                .then();
    }

    @Override
    public Mono<String> sign(KmsAlias alias, byte[] data) {
        log.debug("Signing data with KMS key for alias");
        SignRequest request = SignRequest.builder()
                .keyId(alias.value())
                .message(SdkBytes.fromByteArray(data))
                .messageType(MessageType.RAW)
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                .build();
        return Mono.fromCompletionStage(kmsClient.sign(request))
                .map(response -> Base64.getEncoder()
                        .encodeToString(response.signature().asByteArray()))
                .timeout(Duration.ofSeconds(10))
                .onErrorMap(TimeoutException.class,
                        e -> new PostImportValidationFailedException(
                                "KMS sign operation timed out (ES-07)", e));
    }

    @Override
    public Mono<KmsKeyDescription> describeKey(KmsAlias alias) {
        log.debug("Describing KMS key for alias");
        DescribeKeyRequest request = DescribeKeyRequest.builder()
                .keyId(alias.value())
                .build();
        return Mono.fromCompletionStage(kmsClient.describeKey(request))
                .map(response -> new KmsKeyDescription(
                        response.keyMetadata().keyId(),
                        response.keyMetadata().keyUsageAsString(),
                        response.keyMetadata().enabled()))
                .onErrorMap(NotFoundException.class,
                        e -> new KmsAliasNotProvisionedException(
                                "KMS alias not provisioned (ES-02): " + alias.value(), e));
    }

    @Override
    public Mono<KmsAlias> createKeyV2(String aliasName) {
        log.debug("Creating new KMS key with alias");
        CreateKeyRequest createKeyRequest = CreateKeyRequest.builder()
                .keyUsage(KeyUsageType.SIGN_VERIFY)
                .keySpec(KeySpec.ECC_NIST_P256)
                .origin(OriginType.AWS_KMS)
                .description("DOME signing key " + aliasName)
                .build();
        return Mono.fromCompletionStage(kmsClient.createKey(createKeyRequest))
                .flatMap(createResponse -> {
                    String keyId = createResponse.keyMetadata().keyId();
                    CreateAliasRequest aliasRequest = CreateAliasRequest.builder()
                            .aliasName(aliasName)
                            .targetKeyId(keyId)
                            .build();
                    return Mono.fromCompletionStage(kmsClient.createAlias(aliasRequest));
                })
                .thenReturn(new KmsAlias(aliasName));
    }

    @Override
    public Mono<Void> deleteImportedKeyMaterial(KmsAlias alias) {
        log.debug("Deleting imported key material (best-effort rollback EC-03) for alias");
        DeleteImportedKeyMaterialRequest request = DeleteImportedKeyMaterialRequest.builder()
                .keyId(alias.value())
                .build();
        return Mono.fromCompletionStage(kmsClient.deleteImportedKeyMaterial(request))
                .onErrorComplete()
                .then();
    }

    private static String toPem(byte[] derBytes) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(derBytes);
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----";
    }
}


