package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.RejectionReason;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.KeyState;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.AlgorithmSpec;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DeleteAliasRequest;
import software.amazon.awssdk.services.kms.model.DeleteAliasResponse;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.ExpirationModelType;
import software.amazon.awssdk.services.kms.model.GetParametersForImportRequest;
import software.amazon.awssdk.services.kms.model.GetParametersForImportResponse;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialRequest;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialResponse;
import software.amazon.awssdk.services.kms.model.IncorrectKeyMaterialException;
import software.amazon.awssdk.services.kms.model.KeyMetadata;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.KmsInvalidStateException;
import software.amazon.awssdk.services.kms.model.ListResourceTagsRequest;
import software.amazon.awssdk.services.kms.model.ListResourceTagsResponse;
import software.amazon.awssdk.services.kms.model.NotFoundException;
import software.amazon.awssdk.services.kms.model.OriginType;
import software.amazon.awssdk.services.kms.model.Tag;
import software.amazon.awssdk.services.kms.model.WrappingKeySpec;

import java.time.Instant;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AwsKmsKeyAdministrationAdapterTest {

    private static final String KEY_ARN = "arn:aws:kms:eu-west-1:123456789012:key/abc";

    private final KmsAsyncClient client = mock(KmsAsyncClient.class);
    private final AwsKmsKeyAdministrationAdapter adapter = new AwsKmsKeyAdministrationAdapter(client, null);

    private static <T> CompletableFuture<T> failed(Throwable error) {
        return CompletableFuture.failedFuture(error);
    }

    @Test
    void createKey_requestsAnExternalP256SigningKeyTaggedForTheTenant() {
        when(client.createKey(any(CreateKeyRequest.class))).thenReturn(CompletableFuture.completedFuture(
                CreateKeyResponse.builder().keyMetadata(KeyMetadata.builder().arn(KEY_ARN).build()).build()));

        String arn = adapter.createKey("cgcom", "op-1");

        ArgumentCaptor<CreateKeyRequest> request = ArgumentCaptor.forClass(CreateKeyRequest.class);
        verify(client).createKey(request.capture());
        assertThat(arn).isEqualTo(KEY_ARN);
        assertThat(request.getValue().keySpec()).isEqualTo(KeySpec.ECC_NIST_P256);
        assertThat(request.getValue().keyUsage()).isEqualTo(KeyUsageType.SIGN_VERIFY);
        assertThat(request.getValue().origin()).isEqualTo(OriginType.EXTERNAL);
        assertThat(request.getValue().tags()).containsExactlyInAnyOrder(
                Tag.builder().tagKey("Tenant").tagValue("cgcom").build(),
                Tag.builder().tagKey("operationId").tagValue("op-1").build());
        assertThat(request.getValue().policy()).isNull();
    }

    @Test
    void createKey_withAKeyPolicy_sendsIt() {
        when(client.createKey(any(CreateKeyRequest.class))).thenReturn(CompletableFuture.completedFuture(
                CreateKeyResponse.builder().keyMetadata(KeyMetadata.builder().arn(KEY_ARN).build()).build()));

        new AwsKmsKeyAdministrationAdapter(client, "{\"Version\":\"2012-10-17\"}").createKey("cgcom", "op-1");

        ArgumentCaptor<CreateKeyRequest> request = ArgumentCaptor.forClass(CreateKeyRequest.class);
        verify(client).createKey(request.capture());
        assertThat(request.getValue().policy()).isEqualTo("{\"Version\":\"2012-10-17\"}");
    }

    @Test
    void getParametersForImport_asksForRsaAesKeyWrapSha256WithAnRsa4096Key() {
        Instant validTo = Instant.parse("2026-10-28T12:00:00Z");
        when(client.getParametersForImport(any(GetParametersForImportRequest.class))).thenReturn(
                CompletableFuture.completedFuture(GetParametersForImportResponse.builder()
                        .publicKey(SdkBytes.fromByteArray(new byte[] {1}))
                        .importToken(SdkBytes.fromByteArray(new byte[] {2}))
                        .parametersValidTo(validTo).build()));

        var parameters = adapter.getParametersForImport(KEY_ARN);

        ArgumentCaptor<GetParametersForImportRequest> request = ArgumentCaptor.forClass(GetParametersForImportRequest.class);
        verify(client).getParametersForImport(request.capture());
        assertThat(request.getValue().wrappingAlgorithm()).isEqualTo(AlgorithmSpec.RSA_AES_KEY_WRAP_SHA_256);
        assertThat(request.getValue().wrappingKeySpec()).isEqualTo(WrappingKeySpec.RSA_4096);
        assertThat(parameters.wrappingPublicKeyDer()).containsExactly(1);
        assertThat(parameters.importToken()).containsExactly(2);
        assertThat(parameters.validTo()).isEqualTo(validTo);
    }

    @Test
    void importKeyMaterial_usesKeyMaterialThatDoesNotExpire() {
        when(client.importKeyMaterial(any(ImportKeyMaterialRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(ImportKeyMaterialResponse.builder().build()));

        adapter.importKeyMaterial(KEY_ARN, new byte[] {1}, new byte[] {2});

        ArgumentCaptor<ImportKeyMaterialRequest> request = ArgumentCaptor.forClass(ImportKeyMaterialRequest.class);
        verify(client).importKeyMaterial(request.capture());
        assertThat(request.getValue().expirationModel()).isEqualTo(ExpirationModelType.KEY_MATERIAL_DOES_NOT_EXPIRE);
    }

    @Test
    void importKeyMaterial_kmsRejectsTheMaterial_isARejectionOfTheOnboarding() {
        when(client.importKeyMaterial(any(ImportKeyMaterialRequest.class)))
                .thenReturn(failed(IncorrectKeyMaterialException.builder().message(KEY_ARN).build()));

        assertThatThrownBy(() -> adapter.importKeyMaterial(KEY_ARN, new byte[] {1}, new byte[] {2}))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.INVALID_KEY))
                .hasMessageNotContaining("123456789012");
    }

    @Test
    void importKeyMaterial_otherKmsFailure_isAFailureWithoutTheAwsMessage() {
        var awsError = KmsInvalidStateException.builder().message("key " + KEY_ARN + " is pending")
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("KMSInvalidStateException").build()).build();
        when(client.importKeyMaterial(any(ImportKeyMaterialRequest.class))).thenReturn(failed(awsError));

        assertThatThrownBy(() -> adapter.importKeyMaterial(KEY_ARN, new byte[] {1}, new byte[] {2}))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessage("KMS ImportKeyMaterial failed (KMSInvalidStateException)")
                .hasMessageNotContaining("123456789012");
    }

    @Test
    void describeKeyState_mapsTheStatesTheToolActsOn() {
        assertThat(stateOf("Enabled")).isEqualTo(KeyState.ENABLED);
        assertThat(stateOf("Disabled")).isEqualTo(KeyState.DISABLED);
        assertThat(stateOf("PendingDeletion")).isEqualTo(KeyState.PENDING_DELETION);
        assertThat(stateOf("PendingImport")).isEqualTo(KeyState.PENDING_IMPORT);
        assertThat(stateOf("Unavailable")).isEqualTo(KeyState.OTHER);
    }

    @Test
    void describeKeyState_keyNotFound_isNotFound() {
        when(client.describeKey(any(DescribeKeyRequest.class)))
                .thenReturn(failed(NotFoundException.builder().message("gone").build()));

        assertThat(adapter.describeKeyState(KEY_ARN)).isEqualTo(KeyState.NOT_FOUND);
    }

    @Test
    void describeKeyState_otherFailure_isAFailure() {
        when(client.describeKey(any(DescribeKeyRequest.class))).thenReturn(failed(new IllegalStateException("boom")));

        assertThatThrownBy(() -> adapter.describeKeyState(KEY_ARN))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessage("KMS DescribeKey failed (IllegalStateException)");
    }

    @Test
    void listTags_readsEveryPage() {
        when(client.listResourceTags(any(ListResourceTagsRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(ListResourceTagsResponse.builder()
                        .tags(Tag.builder().tagKey("Tenant").tagValue("cgcom").build())
                        .truncated(true).nextMarker("page-2").build()))
                .thenReturn(CompletableFuture.completedFuture(ListResourceTagsResponse.builder()
                        .tags(Tag.builder().tagKey("operationId").tagValue("op-1").build())
                        .truncated(false).build()));

        assertThat(adapter.listTags(KEY_ARN)).containsEntry("Tenant", "cgcom").containsEntry("operationId", "op-1");
    }

    @Test
    void resolveKeyArn_aliasOfAKey_returnsTheArn() {
        when(client.describeKey(any(DescribeKeyRequest.class))).thenReturn(CompletableFuture.completedFuture(
                DescribeKeyResponse.builder().keyMetadata(KeyMetadata.builder().arn(KEY_ARN).build()).build()));

        assertThat(adapter.resolveKeyArn("alias/own-key-cgcom-op-1")).contains(KEY_ARN);
    }

    @Test
    void resolveKeyArn_aliasThatDoesNotExist_isEmpty() {
        when(client.describeKey(any(DescribeKeyRequest.class)))
                .thenReturn(failed(NotFoundException.builder().message("gone").build()));

        assertThat(adapter.resolveKeyArn("alias/none")).isEmpty();
    }

    @Test
    void deleteAlias_deletesTheAliasByName() {
        when(client.deleteAlias(any(DeleteAliasRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(DeleteAliasResponse.builder().build()));

        adapter.deleteAlias("alias/own-key-cgcom-op-1");

        ArgumentCaptor<DeleteAliasRequest> request = ArgumentCaptor.forClass(DeleteAliasRequest.class);
        verify(client).deleteAlias(request.capture());
        assertThat(request.getValue().aliasName()).isEqualTo("alias/own-key-cgcom-op-1");
    }

    private KeyState stateOf(String kmsState) {
        when(client.describeKey(any(DescribeKeyRequest.class))).thenReturn(CompletableFuture.completedFuture(
                DescribeKeyResponse.builder().keyMetadata(KeyMetadata.builder().keyState(kmsState).build()).build()));
        return adapter.describeKeyState(KEY_ARN);
    }
}
