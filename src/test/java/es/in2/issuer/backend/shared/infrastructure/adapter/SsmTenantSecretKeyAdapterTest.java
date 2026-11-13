package es.in2.issuer.backend.shared.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.exception.TenantSecretKeyUnavailableException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;
import software.amazon.awssdk.services.ssm.model.Parameter;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SsmTenantSecretKeyAdapterTest {

    private static final String PARAMETER = "/eudistack/dev/config/tenants/{tenant}/issuer/search-identifier-key";
    private static final byte[] KEY = "a-tenant-secret-key-of-32-bytes!".getBytes(StandardCharsets.UTF_8);

    @Mock private SsmAsyncClient ssm;

    private SsmTenantSecretKeyAdapter adapter(String parameter) {
        return new SsmTenantSecretKeyAdapter(() -> ssm, parameter);
    }

    private static CompletableFuture<GetParameterResponse> value(String value) {
        return CompletableFuture.completedFuture(GetParameterResponse.builder()
                .parameter(Parameter.builder().value(value).build()).build());
    }

    @Test
    void keyOf_readsTheTenantsDecryptedParameter_andCachesIt() {
        when(ssm.getParameter(any(GetParameterRequest.class))).thenReturn(value(Base64.getEncoder().encodeToString(KEY)));
        SsmTenantSecretKeyAdapter adapter = adapter(PARAMETER);

        StepVerifier.create(adapter.keyOf("cgcom")).assertNext(key -> assertThat(key).isEqualTo(KEY)).verifyComplete();
        StepVerifier.create(adapter.keyOf("cgcom")).assertNext(key -> assertThat(key).isEqualTo(KEY)).verifyComplete();

        ArgumentCaptor<GetParameterRequest> request = ArgumentCaptor.forClass(GetParameterRequest.class);
        verify(ssm, times(1)).getParameter(request.capture());
        assertThat(request.getValue().name()).isEqualTo("/eudistack/dev/config/tenants/cgcom/issuer/search-identifier-key");
        assertThat(request.getValue().withDecryption()).isTrue();
    }

    @Test
    void keyOf_aMissingParameter_isUnavailable_andNotCached() {
        when(ssm.getParameter(any(GetParameterRequest.class)))
                .thenReturn(CompletableFuture.failedFuture(ParameterNotFoundException.builder().message("nope").build()))
                .thenReturn(value(Base64.getEncoder().encodeToString(KEY)));
        SsmTenantSecretKeyAdapter adapter = adapter(PARAMETER);

        StepVerifier.create(adapter.keyOf("kpmg"))
                .verifyErrorSatisfies(e -> assertThat(e).isInstanceOf(TenantSecretKeyUnavailableException.class)
                        .hasMessageContaining("kpmg").hasMessageNotContaining("/eudistack"));
        // Created by infra in the meantime: the next request reads it.
        StepVerifier.create(adapter.keyOf("kpmg")).expectNextCount(1).verifyComplete();
    }

    @Test
    void keyOf_aParameterThatIsNotAKeyOf32Bytes_isUnavailable() {
        when(ssm.getParameter(any(GetParameterRequest.class)))
                .thenReturn(value(Base64.getEncoder().encodeToString("short".getBytes(StandardCharsets.UTF_8))))
                .thenReturn(value("not base64 !"));
        SsmTenantSecretKeyAdapter adapter = adapter(PARAMETER);

        StepVerifier.create(adapter.keyOf("cgcom")).verifyError(TenantSecretKeyUnavailableException.class);
        StepVerifier.create(adapter.keyOf("cgcom")).verifyError(TenantSecretKeyUnavailableException.class);
    }

    @Test
    void keyOf_anyOtherFailureOfParameterStore_isUnavailable() {
        when(ssm.getParameter(any(GetParameterRequest.class)))
                .thenReturn(CompletableFuture.failedFuture(new IllegalStateException("AccessDenied")));

        StepVerifier.create(adapter(PARAMETER).keyOf("cgcom")).verifyError(TenantSecretKeyUnavailableException.class);
    }

    @Test
    void keyOf_withoutAParameterConfigured_isUnavailable_withoutCallingParameterStore() {
        StepVerifier.create(adapter(" ").keyOf("cgcom")).verifyError(TenantSecretKeyUnavailableException.class);
        StepVerifier.create(adapter(null).keyOf("cgcom")).verifyError(TenantSecretKeyUnavailableException.class);

        verify(ssm, never()).getParameter(any(GetParameterRequest.class));
    }

    @Test
    void keyOf_aTenantThatCannotGoIntoAParameterName_isUnavailable() {
        SsmTenantSecretKeyAdapter adapter = adapter(PARAMETER);

        StepVerifier.create(adapter.keyOf("../other")).verifyError(TenantSecretKeyUnavailableException.class);
        StepVerifier.create(adapter.keyOf(null)).verifyError(TenantSecretKeyUnavailableException.class);

        verify(ssm, never()).getParameter(any(GetParameterRequest.class));
    }
}
