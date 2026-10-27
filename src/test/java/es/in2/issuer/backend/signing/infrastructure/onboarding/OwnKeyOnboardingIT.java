package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.ListAliasesRequest;
import software.amazon.awssdk.services.kms.model.ListKeysRequest;
import software.amazon.awssdk.services.kms.model.ListResourceTagsRequest;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.Tag;
import software.amazon.awssdk.services.sts.StsAsyncClient;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.execute;
import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.query;
import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * The onboarding tool end to end, through its command line, against a real Postgres and LocalStack (KMS and
 * STS): {@code prepare}, the customer wrapping its key (RSA-OAEP-SHA256 of an AES key plus AES-KWP of the
 * PKCS#8 key, as with {@code openssl}), {@code import}, a replacement and {@code reconcile}.
 *
 * <p>LocalStack does not enforce what AWS does (it accepts RSA material in an EC key, and its import token
 * does not expire in 24 hours), so those cases are covered by unit tests with the KMS client mocked, and later
 * in Dev.
 */
@Testcontainers
class OwnKeyOnboardingIT {

    private static final DockerImageName LOCALSTACK_IMAGE = DockerImageName.parse("localstack/localstack:4.14.0");
    private static final StaticCredentialsProvider CREDENTIALS =
            StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test"));

    @Container
    static final LocalStackContainer LOCALSTACK = new LocalStackContainer(LOCALSTACK_IMAGE)
            .withServices(LocalStackContainer.EnabledService.named("kms"), LocalStackContainer.EnabledService.named("sts"));

    private static KmsAsyncClient kms;
    private static String callerArn;

    private final OwnKeyTestPki pki = new OwnKeyTestPki();
    private final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    private final ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    private final Map<String, String> env = new HashMap<>();
    private OnboardingCli cli;

    @TempDir
    Path directory;

    /** A key pair and the chain of its certificate, written as PEM. */
    private record Material(KeyPair keyPair, Path chainFile, byte[] spki) {}

    @BeforeAll
    static void connectToLocalStack() throws Exception {
        kms = AwsOnboardingClients.kms(LOCALSTACK.getRegion(), LOCALSTACK.getEndpoint(), CREDENTIALS);
        StsAsyncClient sts = AwsOnboardingClients.sts(LOCALSTACK.getRegion(), LOCALSTACK.getEndpoint(), CREDENTIALS);
        callerArn = sts.getCallerIdentity().get().arn();
        sts.close();
    }

    @AfterAll
    static void closeClient() {
        kms.close();
    }

    @BeforeEach
    void setUp() {
        OnboardingTestDatabase.reset();
        env.put("SPRING_FLYWAY_URL", OnboardingTestDatabase.POSTGRES.getJdbcUrl());
        env.put("SPRING_R2DBC_USERNAME", OnboardingTestDatabase.POSTGRES.getUsername());
        env.put("SPRING_R2DBC_PASSWORD", OnboardingTestDatabase.POSTGRES.getPassword());
        env.put("ISSUER_SIGNING_KMS_REGION", LOCALSTACK.getRegion());
        env.put("ISSUER_SIGNING_KMS_ENDPOINT", LOCALSTACK.getEndpoint().toString());
        cli = new OnboardingCli(new OnboardingWiring(CREDENTIALS), new PrintStream(stdout, true, StandardCharsets.UTF_8),
                new PrintStream(stderr, true, StandardCharsets.UTF_8));
    }

    private int run(String... args) {
        return cli.run(args, env);
    }

    private String err() {
        return stderr.toString(StandardCharsets.UTF_8);
    }

    private Material newMaterial(String name) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keyPair = generator.generateKeyPair();
        var certificate = pki.certificateFor(keyPair.getPublic());
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        return new Material(keyPair, Files.writeString(directory.resolve(name + ".chain.pem"), pem),
                keyPair.getPublic().getEncoded());
    }

    /** Runs {@code prepare} and returns the directory it wrote to. */
    private Path prepare(Material material, String name) throws Exception {
        Path out = Files.createDirectory(directory.resolve(name));
        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", material.chainFile().toString(),
                "--out-dir", out.toString());
        assertThat(exitCode).as(err()).isZero();
        return out;
    }

    private static Path file(Path directory, String suffix) throws Exception {
        try (var files = Files.list(directory)) {
            return files.filter(path -> path.getFileName().toString().endsWith(suffix)).findFirst().orElseThrow();
        }
    }

    /** What the customer does: wraps its private key with the wrapping public key it was given. */
    private Path wrap(Path preparedDirectory, PrivateKey privateKey, String name) throws Exception {
        byte[] wrappingKeyDer = Files.readAllBytes(file(preparedDirectory, ".wrapping-public-key.der"));
        PublicKey wrappingKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(wrappingKeyDer));
        byte[] aesKey = new byte[32];
        new SecureRandom().nextBytes(aesKey);
        Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPPadding");
        oaep.init(Cipher.ENCRYPT_MODE, wrappingKey,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        Cipher keyWrap = Cipher.getInstance("AES/KWP/NoPadding");
        keyWrap.init(Cipher.WRAP_MODE, new SecretKeySpec(aesKey, "AES"));
        byte[] wrappedAesKey = oaep.doFinal(aesKey);
        byte[] wrappedPrivateKey = keyWrap.wrap(privateKey);
        byte[] material = Arrays.copyOf(wrappedAesKey, wrappedAesKey.length + wrappedPrivateKey.length);
        System.arraycopy(wrappedPrivateKey, 0, material, wrappedAesKey.length, wrappedPrivateKey.length);
        return Files.write(directory.resolve(name + ".wrapped"), material);
    }

    private int importKey(Path preparedDirectory, Path wrapped, String... extra) throws Exception {
        String[] args = new String[extra.length + 5];
        args[0] = "import";
        args[1] = "--state";
        args[2] = file(preparedDirectory, ".state.json").toString();
        args[3] = "--key-material";
        args[4] = wrapped.toString();
        System.arraycopy(extra, 0, args, 5, extra.length);
        return run(args);
    }

    private static String keyArnOf(Path preparedDirectory) throws Exception {
        String state = Files.readString(file(preparedDirectory, ".state.json"));
        var matcher = Pattern.compile("\"keyArn\"\\s*:\\s*\"([^\"]+)\"").matcher(state);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private static String keyState(String keyArn) throws Exception {
        return kms.describeKey(DescribeKeyRequest.builder().keyId(keyArn).build()).get().keyMetadata().keyStateAsString();
    }

    private static int keyCount() throws Exception {
        return kms.listKeys(ListKeysRequest.builder().limit(1000).build()).get().keys().size();
    }

    @Test
    void lifecycle_prepareImportReplaceAndReconcile() throws Exception {
        Material first = newMaterial("first");

        // prepare: a key waiting for its material, tagged for the tenant, with an alias and the artifacts for the customer
        Path preparedFirst = prepare(first, "first");
        String firstArn = keyArnOf(preparedFirst);
        assertThat(keyState(firstArn)).isEqualTo("PendingImport");
        assertThat(kms.listResourceTags(ListResourceTagsRequest.builder().keyId(firstArn).build()).get().tags())
                .extracting(Tag::tagKey, Tag::tagValue)
                .contains(tuple("Tenant", "cgcom"));
        assertThat(kms.listResourceTags(ListResourceTagsRequest.builder().keyId(firstArn).build()).get().tags())
                .extracting(Tag::tagKey).contains("operationId");
        assertThat(kms.listAliases(ListAliasesRequest.builder().build()).get().aliases())
                .anyMatch(alias -> alias.aliasName().startsWith("alias/own-key-cgcom-"));
        assertThat(file(preparedFirst, ".wrapping-public-key.pem")).isNotNull();
        assertThat(scalar("SELECT count(*) FROM cgcom_issuer.tenant_signing_config")).isEqualTo(0L);

        // import: the key is the certificate's, and the database says so
        assertThat(importKey(preparedFirst, wrap(preparedFirst, first.keyPair().getPrivate(), "first"))).as(err()).isZero();
        assertThat(keyState(firstArn)).isEqualTo("Enabled");
        assertThat(query("SELECT status, modality, provider, activated_by, own_key_kms_key_ref, own_key_algorithm, "
                + "jsonb_array_length(own_key_certificate_chain) FROM cgcom_issuer.tenant_signing_config"))
                .singleElement().isEqualTo(List.of("active", "own_key", "aws-kms", callerArn, firstArn,
                        "ES256", 1));
        UUID firstConfiguration = (UUID) scalar("SELECT id FROM cgcom_issuer.tenant_signing_config");
        assertThat(query("SELECT tenant_id, signing_configuration_id FROM public.signing_spki_reservation "
                + "WHERE public_key_spki_sha256 = ?", (Object) sha256(first.spki()))).singleElement()
                .isEqualTo(List.of("cgcom", firstConfiguration));
        assertSignatureVerifies(firstArn, first.keyPair().getPublic());

        // replacement: the previous row is withdrawn with who did it, and its reservation is released
        Material second = newMaterial("second");
        Path preparedSecond = prepare(second, "second");
        String secondArn = keyArnOf(preparedSecond);
        assertThat(importKey(preparedSecond, wrap(preparedSecond, second.keyPair().getPrivate(), "second")))
                .as(err()).isZero();
        assertThat(query("SELECT status, withdrawn_by, activated_by FROM cgcom_issuer.tenant_signing_config "
                + "WHERE own_key_kms_key_ref = ?", firstArn)).singleElement()
                .isEqualTo(List.of("withdrawn", callerArn, callerArn));
        assertThat(scalar("SELECT status FROM cgcom_issuer.tenant_signing_config WHERE own_key_kms_key_ref = ?",
                secondArn)).isEqualTo("active");
        assertThat(scalar("SELECT count(*) FROM public.signing_spki_reservation WHERE public_key_spki_sha256 = ?",
                (Object) sha256(first.spki()))).isEqualTo(0L);
        assertThat(scalar("SELECT count(*) FROM public.signing_spki_reservation WHERE public_key_spki_sha256 = ?",
                (Object) sha256(second.spki()))).isEqualTo(1L);
        assertThat(keyState(firstArn)).as("KMS is only touched by reconcile").isEqualTo("Enabled");

        // reconcile: inside the grace period nothing happens; after it the replaced key is retired once
        assertThat(run("reconcile")).isZero();
        assertThat(keyState(firstArn)).isEqualTo("Enabled");
        assertThat(run("reconcile", "--grace-seconds", "0")).as(err()).isZero();
        assertThat(keyState(firstArn)).isEqualTo("PendingDeletion");
        assertThat(keyState(secondArn)).isEqualTo("Enabled");
        assertThat(scalar("SELECT own_key_deleted_at IS NOT NULL FROM cgcom_issuer.tenant_signing_config "
                + "WHERE own_key_kms_key_ref = ?", firstArn)).isEqualTo(true);
        assertThat(scalar("SELECT own_key_deleted_at IS NULL FROM cgcom_issuer.tenant_signing_config "
                + "WHERE own_key_kms_key_ref = ?", secondArn)).isEqualTo(true);
        stdout.reset();
        assertThat(run("reconcile", "--grace-seconds", "0")).isZero();
        assertThat(stdout.toString(StandardCharsets.UTF_8)).contains("keys retired: 0");
    }

    @Test
    void import_keyMaterialThatIsNotTheCertificatesKey_isRejectedAndTheKeyScheduledForDeletion() throws Exception {
        Material certified = newMaterial("certified");
        Material other = newMaterial("other");
        Path prepared = prepare(certified, "mismatch");

        int exitCode = importKey(prepared, wrap(prepared, other.keyPair().getPrivate(), "mismatch"));

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_REJECTED);
        assertThat(err()).contains("REJECTED").contains("public key");
        assertThat(keyState(keyArnOf(prepared))).isEqualTo("PendingDeletion");
        assertThat(scalar("SELECT count(*) FROM cgcom_issuer.tenant_signing_config")).isEqualTo(0L);
        assertThat(scalar("SELECT count(*) FROM public.signing_spki_reservation")).isEqualTo(0L);
    }

    @Test
    void prepare_dryRun_createsNothingInKms() throws Exception {
        Material material = newMaterial("dry");
        int before = keyCount();

        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", material.chainFile().toString(), "--dry-run");

        assertThat(exitCode).as(err()).isZero();
        assertThat(keyCount()).isEqualTo(before);
        assertThat(stdout.toString(StandardCharsets.UTF_8)).contains("dry run");
    }

    @Test
    void prepare_keyAlreadyReserved_isRejectedWithoutCreatingAKey() throws Exception {
        Material material = newMaterial("reserved");
        execute("INSERT INTO public.signing_spki_reservation (public_key_spki_sha256, tenant_id, signing_configuration_id) "
                + "VALUES (?, 'kpmg', ?)", sha256(material.spki()), UUID.randomUUID());
        int before = keyCount();

        int exitCode = run("prepare", "--tenant", "cgcom", "--cert-chain", material.chainFile().toString(),
                "--out-dir", directory.resolve("reserved-out").toString());

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_REJECTED);
        assertThat(err()).contains("already reserved by tenant 'kpmg'");
        assertThat(keyCount()).isEqualTo(before);
    }

    @Test
    void prepare_tenantNotInTheRegistry_isRejected() throws Exception {
        Material material = newMaterial("nobody");

        int exitCode = run("prepare", "--tenant", "nobody", "--cert-chain", material.chainFile().toString(),
                "--out-dir", directory.resolve("nobody-out").toString());

        assertThat(exitCode).isEqualTo(OnboardingCli.EXIT_REJECTED);
        assertThat(err()).contains("not in the tenant registry");
    }

    /** A new certificate, from the same CA, for the key pair of an existing material: a renewal keeping the key. */
    private Material renewedMaterial(Material material, String name) throws Exception {
        var certificate = pki.certificateFor(material.keyPair().getPublic());
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        return new Material(material.keyPair(), Files.writeString(directory.resolve(name + ".chain.pem"), pem),
                material.spki());
    }

    @Test
    void renewal_keepsTheKeyAndReconcileNeverRetiresIt() throws Exception {
        Material first = newMaterial("renew-first");
        Path preparedFirst = prepare(first, "renew-first");
        String arn = keyArnOf(preparedFirst);
        assertThat(importKey(preparedFirst, wrap(preparedFirst, first.keyPair().getPrivate(), "renew-first"))).isZero();
        Material renewed = renewedMaterial(first, "renew-second");
        int keys = keyCount();

        Path out = Files.createDirectory(directory.resolve("renewal"));
        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", renewed.chainFile().toString(), "--out-dir",
                out.toString())).as(err()).isZero();
        assertThat(keyCount()).as("a renewal creates no key").isEqualTo(keys);
        try (var files = Files.list(out)) {
            assertThat(files).hasSize(1);
        }
        assertThat(run("import", "--state", file(out, ".state.json").toString())).as(err()).isZero();

        assertThat(keyArnOf(out)).isEqualTo(arn);
        assertThat(query("SELECT status, own_key_deleted_at IS NOT NULL FROM cgcom_issuer.tenant_signing_config "
                + "ORDER BY created_at")).containsExactly(List.of("withdrawn", true), List.of("active", false));
        assertThat(scalar("SELECT count(DISTINCT own_key_kms_key_ref) FROM cgcom_issuer.tenant_signing_config"))
                .isEqualTo(1L);
        UUID active = (UUID) scalar("SELECT id FROM cgcom_issuer.tenant_signing_config WHERE status = 'active'");
        assertThat(scalar("SELECT signing_configuration_id FROM public.signing_spki_reservation "
                + "WHERE public_key_spki_sha256 = ?", (Object) sha256(first.spki()))).isEqualTo(active);
        assertThat(run("reconcile", "--grace-seconds", "0")).as(err()).isZero();
        assertThat(keyState(arn)).as("the key is still the active one").isEqualTo("Enabled");
        assertSignatureVerifies(arn, first.keyPair().getPublic());
    }

    @Test
    void renewal_certificateOfAnotherKeyForTheSameTenant_isNotARenewal() throws Exception {
        Material first = newMaterial("other-first");
        Path preparedFirst = prepare(first, "other-first");
        assertThat(importKey(preparedFirst, wrap(preparedFirst, first.keyPair().getPrivate(), "other-first"))).isZero();

        Path out = Files.createDirectory(directory.resolve("other-second"));
        assertThat(run("prepare", "--tenant", "cgcom", "--cert-chain", newMaterial("other-second").chainFile().toString(),
                "--out-dir", out.toString())).isZero();

        assertThat(Files.readString(file(out, ".state.json"))).contains("\"renewal\" : false");
        assertThat(keyState(keyArnOf(out))).isEqualTo("PendingImport");
    }

    private void assertSignatureVerifies(String keyArn, PublicKey publicKey) throws Exception {
        byte[] message = "EUD-289 onboarding test".getBytes(StandardCharsets.UTF_8);
        byte[] signature = kms.sign(SignRequest.builder().keyId(keyArn).message(SdkBytes.fromByteArray(message))
                        .messageType(MessageType.RAW).signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256).build())
                .get().signature().asByteArray();
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertThat(verifier.verify(signature)).as("the imported key signs for the certificate").isTrue();
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

}
