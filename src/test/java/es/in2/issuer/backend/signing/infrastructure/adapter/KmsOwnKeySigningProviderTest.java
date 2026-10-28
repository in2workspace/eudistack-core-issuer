package es.in2.issuer.backend.signing.infrastructure.adapter;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningProviderType;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.service.impl.HashGeneratorServiceImpl;
import es.in2.issuer.backend.signing.domain.service.impl.JadesHeaderBuilderServiceImpl;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KmsOwnKeySigningProviderTest {

    private static final String KEY_REF = "arn:aws:kms:eu-west-1:111122223333:key/own-key";
    private static final Clock NOW = Clock.fixed(Instant.parse("2026-06-01T00:00:00Z"), ZoneOffset.UTC);
    private static final OwnKeyTestPki PKI = new OwnKeyTestPki();
    private static final String TENANT = "cgcom";

    /** A KMS stand-in: signs digests with a real P-256 key, as KMS does with MessageType=DIGEST. */
    private static class FakeKms implements KmsSigningPort {
        final AtomicInteger signCalls = new AtomicInteger();
        final KeyPair signingKey;
        String lastKeyRef;

        FakeKms(KeyPair signingKey) {
            this.signingKey = signingKey;
        }

        /** The provider works with the tag cached in the configuration and never reads it from KMS. */
        @Override
        public Mono<String> findTenantTag(String keyRef) {
            return Mono.error(new AssertionError("the provider must not read the key tags"));
        }

        @Override
        public Mono<byte[]> sign(String keyRef, byte[] sha256Digest) {
            signCalls.incrementAndGet();
            lastKeyRef = keyRef;
            try {
                Signature ecdsa = Signature.getInstance("NONEwithECDSA");
                ecdsa.initSign(signingKey.getPrivate());
                ecdsa.update(sha256Digest);
                return Mono.just(ecdsa.sign());
            } catch (Exception e) {
                return Mono.error(e);
            }
        }
    }

    private FakeKms kms;
    private KmsOwnKeySigningProvider provider;
    private final Logger providerLogger = (Logger) LoggerFactory.getLogger(KmsOwnKeySigningProvider.class);
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();

    @BeforeEach
    void setUp() {
        kms = new FakeKms(PKI.validP256Leaf().keyPair());
        provider = providerWith(kms, NOW);
        logs.start();
        providerLogger.addAppender(logs);
    }

    @AfterEach
    void detachAppender() {
        providerLogger.detachAppender(logs);
    }

    /** Signs as the request of tenant {@value #TENANT}: the tenant of the request comes from the Reactor context. */
    private static Mono<SigningResult> signInTenant(
            KmsOwnKeySigningProvider provider, SigningRequest request) {
        return provider.sign(request).contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private static SigningRequest withOwnKey(SigningRequest request, OwnKeySigningConfig config) {
        return SigningRequest.builder()
                .type(request.type()).data(request.data()).context(request.context()).typ(request.typ())
                .ownKey(config).build();
    }

    private static KmsOwnKeySigningProvider providerWith(KmsSigningPort port, Clock clock) {
        @SuppressWarnings("unchecked")
        ObjectProvider<KmsSigningPort> kmsProvider = mock(ObjectProvider.class);
        when(kmsProvider.getIfAvailable()).thenReturn(port);
        return new KmsOwnKeySigningProvider(kmsProvider,
                new JadesHeaderBuilderServiceImpl(new ObjectMapper()),
                new HashGeneratorServiceImpl(),
                new CscSigningProperties(JadesProfile.JADES_B_T),
                clock);
    }

    private static OwnKeySigningConfig configFor(OwnKeyTestPki.Leaf leaf) {
        return configFor(List.of(leaf.certificate()));
    }

    private static OwnKeySigningConfig configFor(List<java.security.cert.X509Certificate> chain) {
        try {
            List<String> encoded = new java.util.ArrayList<>();
            for (var certificate : chain) {
                encoded.add(Base64.getEncoder().encodeToString(certificate.getEncoded()));
            }
            return new OwnKeySigningConfig(KEY_REF, "ES256", encoded, TENANT);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static SigningRequest jades(SigningContext context) {
        return SigningRequest.builder()
                .type(SigningType.JADES)
                .data("{\"iss\":\"did:elsi:VATES-Q0000000X\",\"vct\":\"test\"}")
                .typ("dc+sd-jwt")
                .context(context)
                .build();
    }

    private static void assertReason(Throwable error, SigningFailureReason expected) {
        assertThat(error).isInstanceOf(SigningException.class);
        assertThat(((SigningException) error).getReason()).isEqualTo(expected);
    }

    @Test
    void sign_happyPath_returnsAJwsThatVerifiesWithTheLeafCertificate() {
        var config = configFor(PKI.validP256Leaf());

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), config)))
                .assertNext(result -> {
                    assertThat(result.type()).isEqualTo(SigningType.JADES);
                    try {
                        SignedJWT jwt = SignedJWT.parse(result.data());
                        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
                        assertThat(jwt.getHeader().getType().getType()).isEqualTo("dc+sd-jwt");
                        assertThat(jwt.getHeader().getX509CertChain().stream().map(Object::toString).toList())
                                .isEqualTo(config.certificateChain());
                        assertThat(jwt.getHeader().getCustomParam("sigT")).isNotNull();
                        var publicKey = (ECPublicKey) PKI.validP256Leaf().certificate().getPublicKey();
                        assertThat(jwt.verify(new ECDSAVerifier(publicKey))).isTrue();
                    } catch (Exception e) {
                        throw new AssertionError(e);
                    }
                })
                .verifyComplete();
        assertThat(kms.lastKeyRef).isEqualTo(KEY_REF);
    }

    @Test
    void sign_doesNotNeedTheUserToken_nullOrPopulatedContextBehavesTheSame() {
        var config = configFor(PKI.validP256Leaf());
        var context = new SigningContext("user-token-that-must-not-be-used", "issuance", "a@b.c");

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(context), config))).expectNextCount(1).verifyComplete();
        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), config))).expectNextCount(1).verifyComplete();
    }

    @Test
    void sign_signatureFromAnotherKey_failsWithInvalidResponseAndReturnsNothing() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        provider = providerWith(new FakeKms(generator.generateKeyPair()), NOW);

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(PKI.validP256Leaf()))))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(KmsSigningException.class);
                    assertReason(e, SigningFailureReason.INVALID_RESPONSE);
                })
                .verify();
    }

    @Test
    void sign_malformedSignatureFromKms_failsWithInvalidResponse() {
        KmsSigningPort garbage = new FakeKms(PKI.validP256Leaf().keyPair()) {
            @Override
            public Mono<byte[]> sign(String keyRef, byte[] sha256Digest) {
                return Mono.just(new byte[] {1, 2, 3});
            }
        };
        provider = providerWith(garbage, NOW);

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(PKI.validP256Leaf()))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.INVALID_RESPONSE))
                .verify();
    }

    @Test
    void sign_expiredLeaf_failsWithCertificateInvalidWithoutCallingKms() {
        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(PKI.expiredLeaf()))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_notYetValidLeaf_failsWithCertificateInvalidWithoutCallingKms() {
        provider = providerWith(kms, Clock.fixed(Instant.parse("2023-01-01T00:00:00Z"), ZoneOffset.UTC));

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(PKI.validP256Leaf()))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_nonP256Leaf_failsWithCertificateInvalidWithoutCallingKms() {
        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(PKI.p384Leaf()))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_cose_failsWithUnsupportedAlgorithmWithoutCallingKms() {
        var request = SigningRequest.builder().type(SigningType.COSE).data("00").build();

        StepVerifier.create(signInTenant(provider, withOwnKey(request, configFor(PKI.validP256Leaf()))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.UNSUPPORTED_ALGORITHM))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_kmsReasonFromThePort_reachesTheCallerUnchanged() {
        for (SigningFailureReason reason : List.of(SigningFailureReason.KEY_UNUSABLE,
                SigningFailureReason.PROVIDER_UNAVAILABLE)) {
            var failure = new KmsSigningException(reason, "kms failed");
            KmsSigningPort failing = new FakeKms(PKI.validP256Leaf().keyPair()) {
                @Override
                public Mono<byte[]> sign(String keyRef, byte[] sha256Digest) {
                    return Mono.error(failure);
                }
            };

            StepVerifier.create(signInTenant(providerWith(failing, NOW), withOwnKey(jades(null), configFor(PKI.validP256Leaf()))))
                    .expectErrorSatisfies(e -> assertThat(e).isSameAs(failure))
                    .verify();
        }
    }

    @Test
    void sign_kmsNotEnabled_failsWithKeyUnusable() {
        provider = providerWith(null, NOW);

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(PKI.validP256Leaf()))))
                .expectErrorSatisfies(e -> {
                    assertReason(e, SigningFailureReason.KEY_UNUSABLE);
                    assertThat(e.getMessage()).isEqualTo("KMS signing is not enabled on this issuer");
                })
                .verify();
    }

    @Test
    void supportedProvider_isAwsKms() {
        assertThat(provider.supportedProvider()).isEqualTo(SigningProviderType.AWS_KMS);
    }

    @Test
    void sign_requestWithoutOwnKeyConfiguration_failsWithNoConfiguration() {
        StepVerifier.create(signInTenant(provider, jades(null)))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.NO_CONFIGURATION))
                .verify();
    }

    @Test
    void sign_keyTaggedForTheTenantOfTheRequest_signs() {
        var config = configFor(PKI.validP256Leaf()).withKeyTenantTag("sandbox");

        StepVerifier.create(provider.sign(withOwnKey(jades(null), config))
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .expectNextCount(1)
                .verifyComplete();
        assertThat(kms.signCalls).hasValue(1);
        assertThat(logs.list).noneMatch(e -> e.getFormattedMessage().contains("KEY_TENANT_MISMATCH"));
    }

    @Test
    void sign_keyWithoutTenantTag_failsWithNoConfigurationWithoutCallingKms() {
        var config = configFor(PKI.validP256Leaf()).withKeyTenantTag(null);

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), config)))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.NO_CONFIGURATION))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
        assertThat(mismatchLogs()).singleElement().satisfies(message -> {
            assertThat(message).contains("tenant=cgcom", "keyRef=key/own-key", "keyTenantTag=missing");
            assertThat(message).doesNotContain("111122223333");
        });
    }

    @Test
    void sign_keyTaggedForAnotherTenant_failsWithNoConfigurationWithoutCallingKms() {
        var config = configFor(PKI.validP256Leaf()).withKeyTenantTag("kpmg");

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), config)))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.NO_CONFIGURATION))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
        assertThat(mismatchLogs()).singleElement()
                .satisfies(message -> assertThat(message).contains("tenant=cgcom", "keyTenantTag=kpmg"));
        assertThat(logs.list).filteredOn(e -> e.getLevel() == Level.ERROR).hasSize(1);
    }

    @Test
    void sign_requestWithoutTenantInContext_isNotSignedEvenWithATaggedKey() {
        StepVerifier.create(provider.sign(withOwnKey(jades(null), configFor(PKI.validP256Leaf()))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.NO_CONFIGURATION))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_tenantComparisonIsExact() {
        var config = configFor(PKI.validP256Leaf()).withKeyTenantTag("CGCOM");

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), config)))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.NO_CONFIGURATION))
                .verify();
    }

    private List<String> mismatchLogs() {
        return logs.list.stream()
                .filter(e -> e.getLevel() == Level.ERROR)
                .map(ILoggingEvent::getFormattedMessage)
                .filter(message -> message.startsWith("KEY_TENANT_MISMATCH"))
                .toList();
    }

    @Test
    void sign_chainWithIntermediate_signs() {
        var chain = PKI.chainWithIntermediate();
        provider = providerWith(new FakeKms(chain.leafKeyPair()), NOW);

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(chain.certificates()))))
                .expectNextCount(1)
                .verifyComplete();
    }

    @Test
    void sign_caLeaf_failsWithCertificateInvalidWithoutCallingKms() {
        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(PKI.caLeaf()))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_leafWhoseKeyUsageDoesNotAllowSigning_failsWithCertificateInvalidWithoutCallingKms() {
        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(PKI.certSignOnlyLeaf()))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_chainThatDoesNotLink_failsWithCertificateInvalidWithoutCallingKms() {
        var unrelatedIntermediate = PKI.chainWithIntermediate().certificates().get(1);
        var chain = List.of(PKI.validP256Leaf().certificate(), unrelatedIntermediate);

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(chain))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_expiredIntermediate_failsWithCertificateInvalidWithoutCallingKms() {
        var chain = PKI.chainWithExpiredIntermediate();
        provider = providerWith(new FakeKms(chain.leafKeyPair()), NOW);

        StepVerifier.create(signInTenant(provider, withOwnKey(jades(null), configFor(chain.certificates()))))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
    }
}
