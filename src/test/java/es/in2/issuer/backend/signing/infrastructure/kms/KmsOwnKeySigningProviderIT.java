package es.in2.issuer.backend.signing.infrastructure.kms;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.service.impl.HashGeneratorServiceImpl;
import es.in2.issuer.backend.signing.domain.service.impl.JadesHeaderBuilderServiceImpl;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import es.in2.issuer.backend.signing.infrastructure.adapter.KmsOwnKeySigningProvider;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Own-key provider with the real KMS adapter against LocalStack. The KMS key is created natively
 * (no key material is imported); a test CA issues a certificate for its public key, so the JWS the
 * provider returns must verify with the KMS public key.
 */
@Testcontainers
class KmsOwnKeySigningProviderIT {

    private static final DockerImageName LOCALSTACK_IMAGE = DockerImageName.parse("localstack/localstack:4.14.0");

    @Container
    static final LocalStackContainer LOCALSTACK = new LocalStackContainer(LOCALSTACK_IMAGE)
            .withServices(LocalStackContainer.EnabledService.named("kms"));

    private static KmsSigningProperties properties;
    private static KmsAsyncClient client;

    @BeforeAll
    static void setUpClient() {
        properties = new KmsSigningProperties(true, LOCALSTACK.getRegion(), LOCALSTACK.getEndpoint(),
                Duration.ofSeconds(10), 3, Duration.ofMillis(50), Duration.ofMillis(200));
        client = KmsSigningConfig.clientBuilder(properties)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .build();
    }

    @AfterAll
    static void closeClient() {
        client.close();
    }

    @Test
    void sign_withRealAdapterAndNativeKmsKey_returnsAJwsThatVerifiesWithTheKmsPublicKey() throws Exception {
        String keyId = client.createKey(CreateKeyRequest.builder()
                        .keySpec(KeySpec.ECC_NIST_P256)
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .build())
                .get().keyMetadata().keyId();
        KmsSigningPort adapter = new KmsSigningAdapter(client, properties);
        byte[] spki = client.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build())
                .get().publicKey().asByteArray();
        ECPublicKey kmsPublicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
        var certificate = new OwnKeyTestPki().certificateFor(kmsPublicKey);
        var config = new OwnKeySigningConfig(keyId, "ES256",
                List.of(Base64.getEncoder().encodeToString(certificate.getEncoded())),
                spkiSha256Hex(certificate));

        @SuppressWarnings("unchecked")
        ObjectProvider<KmsSigningPort> port = mock(ObjectProvider.class);
        when(port.getIfAvailable()).thenReturn(adapter);
        var provider = new KmsOwnKeySigningProvider(port,
                new JadesHeaderBuilderServiceImpl(new ObjectMapper()),
                new HashGeneratorServiceImpl(),
                new CscSigningProperties(JadesProfile.JADES_B_T),
                Clock.systemUTC());

        var result = provider.sign(SigningRequest.builder()
                .type(SigningType.JADES).data("{\"vct\":\"test\"}").typ("dc+sd-jwt").build(), config)
                .block(Duration.ofSeconds(30));

        assertThat(result).isNotNull();
        assertThat(SignedJWT.parse(result.data()).verify(new ECDSAVerifier(kmsPublicKey))).isTrue();
    }

    private static String spkiSha256Hex(X509Certificate certificate) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(certificate.getPublicKey().getEncoded()));
    }
}
