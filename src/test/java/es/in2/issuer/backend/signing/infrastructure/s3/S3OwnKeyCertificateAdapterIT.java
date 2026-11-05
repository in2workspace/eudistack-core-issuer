package es.in2.issuer.backend.signing.infrastructure.s3;

import es.in2.issuer.backend.signing.infrastructure.properties.OwnKeyCertificateProperties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import reactor.test.StepVerifier;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;


/**
 * The certificate read against LocalStack S3, with the client the Issuer builds. LocalStack proves the
 * S3 API path only; it does not model IAM, so the 403 of a missing object without {@code s3:ListBucket}
 * is not reproduced here.
 */
@Testcontainers
class S3OwnKeyCertificateAdapterIT {

    // Last LocalStack tag that runs without an auth token.
    private static final DockerImageName LOCALSTACK_IMAGE = DockerImageName.parse("localstack/localstack:4.14.0");
    private static final String BUCKET = "own-key-certificates";
    private static final String PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    @Container
    static final LocalStackContainer LOCALSTACK = new LocalStackContainer(LOCALSTACK_IMAGE)
            .withServices(LocalStackContainer.EnabledService.named("s3"));

    private static S3AsyncClient client;
    private static S3OwnKeyCertificateAdapter adapter;

    @BeforeAll
    static void setUp() {
        var properties = new OwnKeyCertificateProperties("arn:aws:s3:::" + BUCKET + "/issuer",
                LOCALSTACK.getEndpoint());
        client = OwnKeyCertificateConfig.clientBuilder(properties)
                .region(Region.of(LOCALSTACK.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .build();
        adapter = new S3OwnKeyCertificateAdapter(client, properties);
        client.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build()).join();
        client.putObject(PutObjectRequest.builder().bucket(BUCKET).key("issuer/cgcom/latest/cert.pem").build(),
                AsyncRequestBody.fromString(PEM)).join();
    }

    @AfterAll
    static void closeClient() {
        client.close();
    }

    @Test
    void findCertificateChainPem_publishedCertificate_isRead() {
        StepVerifier.create(adapter.findCertificateChainPem("cgcom"))
                .expectNext(PEM)
                .verifyComplete();
    }

    @Test
    void findCertificateChainPem_tenantWithoutCertificate_isEmpty() {
        StepVerifier.create(adapter.findCertificateChainPem("kpmg")).verifyComplete();
    }
}
