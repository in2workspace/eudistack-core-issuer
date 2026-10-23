package es.in2.issuer.backend.signing.infrastructure.kms;

import com.nimbusds.jose.JWSAlgorithm;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.util.JwsSignatureEncoder;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.AdditionalAnswers;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import reactor.test.StepVerifier;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.DisableKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.SignRequest;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Signing path against LocalStack. LocalStack proves the KMS API path only; it does not model
 * AWS validations, limits or IAM (notas-tecnicas §6), and it cannot inject delays or throttling.
 */
@Testcontainers
class KmsSigningAdapterIT {

    // Last LocalStack tag that runs without an auth token.
    private static final DockerImageName LOCALSTACK_IMAGE = DockerImageName.parse("localstack/localstack:4.14.0");

    @Container
    static final LocalStackContainer LOCALSTACK = new LocalStackContainer(LOCALSTACK_IMAGE).withServices(LocalStackContainer.EnabledService.named("kms"));

    private static KmsSigningProperties properties;
    private static KmsAsyncClient plainClient;

    @BeforeAll
    static void setUpClient() {
        properties = new KmsSigningProperties(true, LOCALSTACK.getRegion(), LOCALSTACK.getEndpoint(),
                Duration.ofSeconds(10), 3, Duration.ofMillis(50), Duration.ofMillis(200));
        plainClient = KmsSigningConfig.clientBuilder(properties)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .build();
    }

    @AfterAll
    static void closeClient() {
        plainClient.close();
    }

    @Test
    void sign_digestWithNativeP256Key_signatureVerifiesWithPublicKeyAndConvertsToJose() throws Exception {
        String keyId = createP256Key();
        KmsSigningAdapter adapter = new KmsSigningAdapter(plainClient, properties);
        byte[] message = "header.payload".getBytes(StandardCharsets.UTF_8);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message);

        byte[] der = adapter.sign(keyId, digest).block(Duration.ofSeconds(30));
        byte[] spki = plainClient.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build())
                .get().publicKey().asByteArray();

        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
        Signature overDigest = Signature.getInstance("NONEwithECDSA");
        overDigest.initVerify(publicKey);
        overDigest.update(digest);
        assertThat(overDigest.verify(der)).isTrue();
        Signature overMessage = Signature.getInstance("SHA256withECDSA");
        overMessage.initVerify(publicKey);
        overMessage.update(message);
        assertThat(overMessage.verify(der)).isTrue();

        String jose = JwsSignatureEncoder.toJoseSignature(Base64.getEncoder().encodeToString(der), JWSAlgorithm.ES256);
        assertThat(Base64.getUrlDecoder().decode(jose)).hasSize(64);
    }

    @Test
    void sign_disabledKey_failsKeyUnusableWithExactlyOneCall() throws Exception {
        String keyId = createP256Key();
        plainClient.disableKey(DisableKeyRequest.builder().keyId(keyId).build()).get();
        KmsAsyncClient countingClient = mock(KmsAsyncClient.class, AdditionalAnswers.delegatesTo(plainClient));
        KmsSigningAdapter adapter = new KmsSigningAdapter(countingClient, properties);

        StepVerifier.create(adapter.sign(keyId, new byte[32]))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(KmsSigningException.class);
                    assertThat(((KmsSigningException) ex).getReason()).isEqualTo(SigningFailureReason.KEY_UNUSABLE);
                })
                .verify(Duration.ofSeconds(30));

        verify(countingClient, times(1)).sign(any(SignRequest.class));
    }

    private static String createP256Key() throws Exception {
        return plainClient.createKey(CreateKeyRequest.builder()
                        .keySpec(KeySpec.ECC_NIST_P256)
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .build())
                .get().keyMetadata().keyId();
    }
}
