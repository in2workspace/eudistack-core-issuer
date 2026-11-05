package es.in2.issuer.backend.signing.infrastructure.s3;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.infrastructure.properties.OwnKeyCertificateProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import reactor.test.StepVerifier;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class S3OwnKeyCertificateAdapterTest {

    private static final String PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    private final S3AsyncClient client = mock(S3AsyncClient.class);

    private S3OwnKeyCertificateAdapter adapterAt(String arn) {
        return new S3OwnKeyCertificateAdapter(client,
                new OwnKeyCertificateProperties(arn, null));
    }

    @SuppressWarnings("unchecked")
    private void answer(CompletableFuture<ResponseBytes<GetObjectResponse>> response) {
        when(client.getObject(any(GetObjectRequest.class), any(AsyncResponseTransformer.class))).thenReturn(response);
    }

    private static <T> CompletableFuture<T> failed(Throwable error) {
        return CompletableFuture.failedFuture(error);
    }

    @Test
    @SuppressWarnings("unchecked")
    void findCertificateChainPem_readsLatestUnderThePrefixAndTheTenant() {
        answer(CompletableFuture.completedFuture(ResponseBytes.fromByteArray(GetObjectResponse.builder().build(),
                PEM.getBytes(StandardCharsets.US_ASCII))));

        StepVerifier.create(adapterAt("arn:aws:s3:::certs-bucket/issuer/own-key").findCertificateChainPem("cgcom"))
                .expectNext(PEM)
                .verifyComplete();

        ArgumentCaptor<GetObjectRequest> request = ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(client).getObject(request.capture(), any(AsyncResponseTransformer.class));
        assertThat(request.getValue().bucket()).isEqualTo("certs-bucket");
        assertThat(request.getValue().key()).isEqualTo("issuer/own-key/cgcom/latest/cert.pem");
    }

    @Test
    void objectKey_withoutPrefix_isTheTenantFolder() {
        assertThat(adapterAt("arn:aws:s3:::certs-bucket").objectKey("cgcom")).isEqualTo("cgcom/latest/cert.pem");
        assertThat(adapterAt("arn:aws:s3:::certs-bucket/").objectKey("cgcom")).isEqualTo("cgcom/latest/cert.pem");
    }

    @Test
    void findCertificateChainPem_missingObject_isEmpty() {
        answer(failed(NoSuchKeyException.builder().message("missing").build()));

        StepVerifier.create(adapterAt("arn:aws:s3:::certs-bucket/p").findCertificateChainPem("cgcom")).verifyComplete();
    }

    @Test
    void findCertificateChainPem_accessDenied_isNoConfiguration() {
        answer(failed(S3Exception.builder().statusCode(403).message("denied").build()));

        StepVerifier.create(adapterAt("arn:aws:s3:::certs-bucket/p").findCertificateChainPem("cgcom"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOfSatisfying(SigningException.class,
                        s -> assertThat(s.getReason()).isEqualTo(SigningFailureReason.NO_CONFIGURATION)))
                .verify();
    }

    @Test
    void findCertificateChainPem_otherFailure_isProviderUnavailable() {
        answer(failed(SdkClientException.create("timeout")));

        StepVerifier.create(adapterAt("arn:aws:s3:::certs-bucket/p").findCertificateChainPem("cgcom"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOfSatisfying(SigningException.class,
                        s -> assertThat(s.getReason()).isEqualTo(SigningFailureReason.PROVIDER_UNAVAILABLE)))
                .verify();
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "../kpmg", "cgcom/../kpmg", "CGCOM", "unknown tenant"})
    void findCertificateChainPem_tenantThatCannotNameAFolder_isNoConfigurationWithoutReading(String tenant) {
        StepVerifier.create(adapterAt("arn:aws:s3:::certs-bucket/p").findCertificateChainPem(tenant))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOfSatisfying(SigningException.class,
                        s -> assertThat(s.getReason()).isEqualTo(SigningFailureReason.NO_CONFIGURATION)))
                .verify();
        verifyNoInteractions(client);
    }
}
