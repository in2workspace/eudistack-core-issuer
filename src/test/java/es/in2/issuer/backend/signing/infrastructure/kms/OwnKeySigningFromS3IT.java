package es.in2.issuer.backend.signing.infrastructure.kms;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.service.impl.HashGeneratorServiceImpl;
import es.in2.issuer.backend.signing.domain.service.impl.JadesHeaderBuilderServiceImpl;
import es.in2.issuer.backend.signing.domain.service.impl.OwnKeySigningConfigLoaderImpl;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyCertificatePort;
import es.in2.issuer.backend.signing.domain.util.OwnKeyCertificates;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import es.in2.issuer.backend.signing.infrastructure.adapter.KmsOwnKeySigningProvider;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.OwnKeyCertificateProperties;
import es.in2.issuer.backend.signing.infrastructure.s3.S3OwnKeyCertificateAdapter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.CreateAliasRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The own-key path as infra sets it up, against LocalStack: a KMS key with the alias derived from its
 * certificate, and the certificate in S3. The configuration is loaded from S3 and the provider signs
 * with the key by its alias; the JWS must verify with the KMS public key.
 */
@Testcontainers
class OwnKeySigningFromS3IT {

    private static final DockerImageName LOCALSTACK_IMAGE = DockerImageName.parse("localstack/localstack:4.14.0");
    private static final String BUCKET = "own-key-certificates";
    private static final String TENANT = "cgcom";

    @Container
    static final LocalStackContainer LOCALSTACK = new LocalStackContainer(LOCALSTACK_IMAGE)
            .withServices(LocalStackContainer.EnabledService.named("kms"), LocalStackContainer.EnabledService.named("s3"));

    private static final StaticCredentialsProvider CREDENTIALS =
            StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test"));

    private static KmsSigningProperties kmsProperties;
    private static KmsAsyncClient kms;
    private static S3AsyncClient s3;

    @BeforeAll
    static void setUpClients() {
        kmsProperties = new KmsSigningProperties(LOCALSTACK.getEndpoint());
        kms = KmsSigningConfig.clientBuilder(kmsProperties).region(Region.of(LOCALSTACK.getRegion()))
                .credentialsProvider(CREDENTIALS).build();
        s3 = S3AsyncClient.builder().region(Region.of(LOCALSTACK.getRegion())).endpointOverride(LOCALSTACK.getEndpoint())
                .forcePathStyle(true).credentialsProvider(CREDENTIALS).build();
        s3.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build()).join();
    }

    @AfterAll
    static void closeClients() {
        kms.close();
        s3.close();
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> providerOf(T bean) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(bean);
        return provider;
    }

    @Test
    void sign_withTheCertificateFromS3_signsWithTheKeyOfItsAlias() throws Exception {
        // What infra does: a key, a certificate for its public key, the alias and the certificate in S3.
        String keyId = kms.createKey(CreateKeyRequest.builder()
                .keySpec(KeySpec.ECC_NIST_P256).keyUsage(KeyUsageType.SIGN_VERIFY).build()).get().keyMetadata().keyId();
        byte[] spki = kms.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build()).get().publicKey().asByteArray();
        ECPublicKey kmsPublicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
        var certificate = new OwnKeyTestPki().certificateFor(kmsPublicKey);
        kms.createAlias(CreateAliasRequest.builder()
                .aliasName(OwnKeyCertificates.keyAlias(certificate)).targetKeyId(keyId).build()).get();
        String pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        s3.putObject(PutObjectRequest.builder().bucket(BUCKET).key("issuer/" + TENANT + "/latest/cert.pem").build(),
                AsyncRequestBody.fromString(pem)).join();

        OwnKeyCertificatePort certificates = new S3OwnKeyCertificateAdapter(s3, new OwnKeyCertificateProperties(
                "arn:aws:s3:::" + BUCKET + "/issuer", LOCALSTACK.getEndpoint()));
        TenantConfigService tenantConfig = mock(TenantConfigService.class);
        when(tenantConfig.getStringOrThrow("admin_organization_id"))
                .thenReturn(Mono.just(OwnKeyTestPki.ORGANIZATION_IDENTIFIER));
        OwnKeySigningConfig config = new OwnKeySigningConfigLoaderImpl(providerOf(certificates), tenantConfig)
                .load(TENANT).block(Duration.ofSeconds(30));

        KmsSigningPort adapter = new KmsSigningAdapter(() -> kms);
        var provider = new KmsOwnKeySigningProvider(adapter,
                new JadesHeaderBuilderServiceImpl(new ObjectMapper()),
                new HashGeneratorServiceImpl(),
                new CscSigningProperties(JadesProfile.JADES_B_T),
                Clock.systemUTC());
        var result = provider.sign(SigningRequest.builder()
                        .type(SigningType.JADES).data("{\"vct\":\"test\"}").typ("dc+sd-jwt").ownKey(config).build())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block(Duration.ofSeconds(30));

        assertThat(config).isNotNull();
        assertThat(config.kmsKeyRef()).isEqualTo(OwnKeyCertificates.keyAlias(certificate));
        assertThat(result).isNotNull();
        assertThat(SignedJWT.parse(result.data()).verify(new ECDSAVerifier(kmsPublicKey))).isTrue();
    }
}
