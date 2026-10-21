package es.in2.issuer.backend.signing.infrastructure.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.service.impl.HashGeneratorServiceImpl;
import es.in2.issuer.backend.signing.domain.service.impl.JadesHeaderBuilderServiceImpl;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

    /** A KMS stand-in: signs digests with a real P-256 key, as KMS does with MessageType=DIGEST. */
    private static class FakeKms implements KmsSigningPort {
        final AtomicInteger signCalls = new AtomicInteger();
        final KeyPair signingKey;
        String lastKeyRef;

        FakeKms(KeyPair signingKey) {
            this.signingKey = signingKey;
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

        @Override
        public Mono<byte[]> publicKey(String keyRef) {
            return Mono.just(signingKey.getPublic().getEncoded());
        }
    }

    private FakeKms kms;
    private KmsOwnKeySigningProvider provider;

    @BeforeEach
    void setUp() {
        kms = new FakeKms(PKI.validP256Leaf().keyPair());
        provider = providerWith(kms, NOW);
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
        try {
            return new OwnKeySigningConfig(KEY_REF, "ES256",
                    List.of(Base64.getEncoder().encodeToString(leaf.certificate().getEncoded())),
                    null, null, null, null, null, "a".repeat(64));
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

        StepVerifier.create(provider.sign(jades(null), config))
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

        StepVerifier.create(provider.sign(jades(context), config)).expectNextCount(1).verifyComplete();
        StepVerifier.create(provider.sign(jades(null), config)).expectNextCount(1).verifyComplete();
    }

    @Test
    void sign_signatureFromAnotherKey_failsWithInvalidResponseAndReturnsNothing() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        provider = providerWith(new FakeKms(generator.generateKeyPair()), NOW);

        StepVerifier.create(provider.sign(jades(null), configFor(PKI.validP256Leaf())))
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

        StepVerifier.create(provider.sign(jades(null), configFor(PKI.validP256Leaf())))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.INVALID_RESPONSE))
                .verify();
    }

    @Test
    void sign_expiredLeaf_failsWithCertificateInvalidWithoutCallingKms() {
        StepVerifier.create(provider.sign(jades(null), configFor(PKI.expiredLeaf())))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_notYetValidLeaf_failsWithCertificateInvalidWithoutCallingKms() {
        provider = providerWith(kms, Clock.fixed(Instant.parse("2023-01-01T00:00:00Z"), ZoneOffset.UTC));

        StepVerifier.create(provider.sign(jades(null), configFor(PKI.validP256Leaf())))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_nonP256Leaf_failsWithCertificateInvalidWithoutCallingKms() {
        StepVerifier.create(provider.sign(jades(null), configFor(PKI.p384Leaf())))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_cose_failsWithUnsupportedAlgorithmWithoutCallingKms() {
        var request = SigningRequest.builder().type(SigningType.COSE).data("00").build();

        StepVerifier.create(provider.sign(request, configFor(PKI.validP256Leaf())))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.UNSUPPORTED_ALGORITHM))
                .verify();
        assertThat(kms.signCalls).hasValue(0);
    }

    @Test
    void sign_kmsReasonFromThePort_reachesTheCallerUnchanged() {
        for (SigningFailureReason reason : List.of(SigningFailureReason.KEY_UNUSABLE,
                SigningFailureReason.SERVICE_UNAVAILABLE)) {
            var failure = new KmsSigningException(reason, "kms failed");
            KmsSigningPort failing = new FakeKms(PKI.validP256Leaf().keyPair()) {
                @Override
                public Mono<byte[]> sign(String keyRef, byte[] sha256Digest) {
                    return Mono.error(failure);
                }
            };

            StepVerifier.create(providerWith(failing, NOW).sign(jades(null), configFor(PKI.validP256Leaf())))
                    .expectErrorSatisfies(e -> assertThat(e).isSameAs(failure))
                    .verify();
        }
    }

    @Test
    void sign_kmsNotEnabled_failsWithKeyUnusable() {
        provider = providerWith(null, NOW);

        StepVerifier.create(provider.sign(jades(null), configFor(PKI.validP256Leaf())))
                .expectErrorSatisfies(e -> {
                    assertReason(e, SigningFailureReason.KEY_UNUSABLE);
                    assertThat(e.getMessage()).isEqualTo("KMS signing is not enabled on this issuer");
                })
                .verify();
    }

    @Test
    void sign_withTenantInReactorContext_stillSigns() {
        StepVerifier.create(provider.sign(jades(null), configFor(PKI.validP256Leaf()))
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .expectNextCount(1)
                .verifyComplete();
    }
}
