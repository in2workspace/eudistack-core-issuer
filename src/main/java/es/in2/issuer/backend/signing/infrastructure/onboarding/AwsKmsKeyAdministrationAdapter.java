package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.RejectionReason;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.AlgorithmSpec;
import software.amazon.awssdk.services.kms.model.CreateAliasRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.DeleteAliasRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DisableKeyRequest;
import software.amazon.awssdk.services.kms.model.ExpirationModelType;
import software.amazon.awssdk.services.kms.model.GetParametersForImportRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialRequest;
import software.amazon.awssdk.services.kms.model.IncorrectKeyMaterialException;
import software.amazon.awssdk.services.kms.model.InvalidCiphertextException;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.ListResourceTagsRequest;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.NotFoundException;
import software.amazon.awssdk.services.kms.model.OriginType;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionRequest;
import software.amazon.awssdk.services.kms.model.Tag;
import software.amazon.awssdk.services.kms.model.WrappingKeySpec;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;

/**
 * {@link KmsKeyAdministrationPort} over the AWS KMS async client, blocking on each call: the tool is a
 * short-lived process that does one thing at a time. SDK retries stay at their default here (an
 * administration call is not on the signing path).
 *
 * <p>Error messages are not copied: those of AWS carry key ARNs and account ids. Only the operation and
 * the error code or exception type are reported.
 *
 * <p>The key policy is the KMS default unless one is given. Infra will define a fixed policy (the roles of
 * the Issuer and of the operation); it goes in through the constructor, so adopting it changes no caller.
 */
public class AwsKmsKeyAdministrationAdapter implements KmsKeyAdministrationPort {

    /** Tag the Issuer checks before signing: its value is the tenant the key belongs to (M1). */
    static final String TENANT_TAG_KEY = "Tenant";
    static final String OPERATION_ID_TAG_KEY = "operationId";

    private final KmsAsyncClient client;
    private final String keyPolicy;

    /** @param keyPolicy JSON key policy; {@code null} leaves the KMS default */
    public AwsKmsKeyAdministrationAdapter(KmsAsyncClient client, String keyPolicy) {
        this.client = client;
        this.keyPolicy = keyPolicy;
    }

    @Override
    public String createKey(String tenant, String operationId) {
        CreateKeyRequest.Builder request = CreateKeyRequest.builder()
                .keySpec(KeySpec.ECC_NIST_P256)
                .keyUsage(KeyUsageType.SIGN_VERIFY)
                .origin(OriginType.EXTERNAL)
                .description("EUDIStack own signing key of tenant " + tenant + " (onboarding " + operationId + ")")
                .tags(Tag.builder().tagKey(TENANT_TAG_KEY).tagValue(tenant).build(),
                        Tag.builder().tagKey(OPERATION_ID_TAG_KEY).tagValue(operationId).build());
        if (keyPolicy != null) {
            request.policy(keyPolicy);
        }
        return call("CreateKey", () -> client.createKey(request.build())).keyMetadata().arn();
    }

    @Override
    public void createAlias(String alias, String keyArn) {
        call("CreateAlias", () -> client.createAlias(CreateAliasRequest.builder()
                .aliasName(alias).targetKeyId(keyArn).build()));
    }

    @Override
    public ImportParameters getParametersForImport(String keyArn) {
        var response = call("GetParametersForImport", () -> client.getParametersForImport(
                GetParametersForImportRequest.builder()
                        .keyId(keyArn)
                        .wrappingAlgorithm(AlgorithmSpec.RSA_AES_KEY_WRAP_SHA_256)
                        .wrappingKeySpec(WrappingKeySpec.RSA_4096)
                        .build()));
        return new ImportParameters(response.publicKey().asByteArray(), response.importToken().asByteArray(),
                response.parametersValidTo());
    }

    /**
     * KMS refusing the material (for example a key that is not P-256, or material not wrapped as announced)
     * is a rejection of the onboarding, not a failure of the tool (H-5).
     */
    @Override
    public void importKeyMaterial(String keyArn, byte[] importToken, byte[] encryptedKeyMaterial) {
        try {
            call("ImportKeyMaterial", () -> client.importKeyMaterial(ImportKeyMaterialRequest.builder()
                    .keyId(keyArn)
                    .importToken(SdkBytes.fromByteArray(importToken))
                    .encryptedKeyMaterial(SdkBytes.fromByteArray(encryptedKeyMaterial))
                    .expirationModel(ExpirationModelType.KEY_MATERIAL_DOES_NOT_EXPIRE)
                    .build()));
        } catch (OnboardingFailedException e) {
            if (e.getCause() instanceof IncorrectKeyMaterialException
                    || e.getCause() instanceof InvalidCiphertextException) {
                throw new OnboardingRejectedException(RejectionReason.INVALID_KEY,
                        "KMS refused the key material (" + e.getCause().getClass().getSimpleName()
                                + "): it is not an EC P-256 private key wrapped with the wrapping key of this onboarding");
            }
            throw e;
        }
    }

    @Override
    public byte[] getPublicKey(String keyArn) {
        return call("GetPublicKey", () -> client.getPublicKey(GetPublicKeyRequest.builder().keyId(keyArn).build()))
                .publicKey().asByteArray();
    }

    @Override
    public KeyState describeKeyState(String keyArn) {
        try {
            var state = call("DescribeKey", () -> client.describeKey(DescribeKeyRequest.builder().keyId(keyArn).build()))
                    .keyMetadata().keyState();
            return switch (state) {
                case ENABLED -> KeyState.ENABLED;
                case DISABLED -> KeyState.DISABLED;
                case PENDING_DELETION -> KeyState.PENDING_DELETION;
                case PENDING_IMPORT -> KeyState.PENDING_IMPORT;
                default -> KeyState.OTHER;
            };
        } catch (OnboardingFailedException e) {
            if (e.getCause() instanceof NotFoundException) {
                return KeyState.NOT_FOUND;
            }
            throw e;
        }
    }

    @Override
    public Optional<String> resolveKeyArn(String keyIdOrAlias) {
        try {
            return Optional.ofNullable(call("DescribeKey", () -> client.describeKey(
                    DescribeKeyRequest.builder().keyId(keyIdOrAlias).build())).keyMetadata().arn());
        } catch (OnboardingFailedException e) {
            if (e.getCause() instanceof NotFoundException) {
                return Optional.empty();
            }
            throw e;
        }
    }

    @Override
    public Map<String, String> listTags(String keyArn) {
        Map<String, String> tags = new HashMap<>();
        String marker = null;
        do {
            String currentMarker = marker;
            var page = call("ListResourceTags", () -> client.listResourceTags(
                    ListResourceTagsRequest.builder().keyId(keyArn).marker(currentMarker).build()));
            page.tags().forEach(tag -> tags.put(tag.tagKey(), tag.tagValue()));
            marker = Boolean.TRUE.equals(page.truncated()) ? page.nextMarker() : null;
        } while (marker != null);
        return tags;
    }

    @Override
    public void deleteAlias(String alias) {
        call("DeleteAlias", () -> client.deleteAlias(DeleteAliasRequest.builder().aliasName(alias).build()));
    }

    @Override
    public void disableKey(String keyArn) {
        call("DisableKey", () -> client.disableKey(DisableKeyRequest.builder().keyId(keyArn).build()));
    }

    @Override
    public void scheduleKeyDeletion(String keyArn, int pendingWindowDays) {
        call("ScheduleKeyDeletion", () -> client.scheduleKeyDeletion(ScheduleKeyDeletionRequest.builder()
                .keyId(keyArn).pendingWindowInDays(pendingWindowDays).build()));
    }

    private static <T> T call(String operation, Supplier<CompletableFuture<T>> request) {
        try {
            return request.get().join();
        } catch (CompletionException e) {
            throw failure(operation, e.getCause() != null ? e.getCause() : e);
        } catch (RuntimeException e) {
            throw failure(operation, e);
        }
    }

    /** The cause is kept (so the caller can classify it); its message is not, because AWS puts ARNs in it. */
    private static OnboardingFailedException failure(String operation, Throwable cause) {
        String detail = cause instanceof AwsServiceException aws && aws.awsErrorDetails() != null
                ? aws.awsErrorDetails().errorCode()
                : cause.getClass().getSimpleName();
        return new OnboardingFailedException("KMS " + operation + " failed (" + detail + ")", cause);
    }
}
