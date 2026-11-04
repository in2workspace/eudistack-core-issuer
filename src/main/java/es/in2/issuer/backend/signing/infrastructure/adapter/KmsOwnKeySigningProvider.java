package es.in2.issuer.backend.signing.infrastructure.adapter;

import com.nimbusds.jose.JWSAlgorithm;
import es.in2.issuer.backend.signing.domain.exception.CertificateCheckException;
import es.in2.issuer.backend.signing.domain.exception.HashGenerationException;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.CertificateCheck;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import es.in2.issuer.backend.signing.domain.util.Es256SignatureVerifier;
import es.in2.issuer.backend.signing.domain.util.JwsSignatureEncoder;
import es.in2.issuer.backend.signing.domain.util.SigningCertificateChecks;
import es.in2.issuer.backend.signing.domain.util.StoredCertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.kms.KmsKeyRefs;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Signs a JAdES JWS with the tenant's own ES256 key held in KMS.
 *
 * <p>The provider of the own-key modality in {@code SigningProviderResolver}.
 * {@code DelegatingSigningProviderImpl} resolves it for that modality and puts the tenant's own-key
 * configuration in {@link SigningRequest#ownKey()}.
 *
 * <p>No user token is used: the KMS authorizes with the issuer's runtime role.
 * The returned signature is always verified against the leaf certificate of the configuration first, so a
 * signature the credential's {@code x5c} could not validate is never returned.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KmsOwnKeySigningProvider implements SigningProvider {

    private static final String UNKNOWN_TENANT = "unknown";

    /** The port exists only when {@code issuer.signing.kms.enabled=true}. */
    private final ObjectProvider<KmsSigningPort> kmsSigningPort;
    private final JadesHeaderBuilderService jadesHeaderBuilderService;
    private final HashGeneratorService hashGeneratorService;
    private final CscSigningProperties cscSigningProperties;
    private final Clock clock;

    @Override
    public SigningModality modality() {
        return SigningModality.OWN_KEY;
    }

    /** The chain of the configuration, read with it; no network call. */
    @Override
    public Mono<List<String>> resolveChain(ActiveSigningConfig config) {
        return config.ownKey() == null ? Mono.empty() : Mono.just(config.ownKey().certificateChain());
    }

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, UNKNOWN_TENANT);
            if (request.ownKey() == null) {
                return Mono.error(new SigningException(SigningFailureReason.NO_CONFIGURATION,
                        "The signing request carries no own-key configuration"));
            }
            return signAs(tenant, request, request.ownKey());
        });
    }

    private Mono<SigningResult> signAs(String tenant, SigningRequest request, OwnKeySigningConfig config) {
        if (request.type() != SigningType.JADES) {
            return Mono.error(new SigningException(SigningFailureReason.UNSUPPORTED_ALGORITHM,
                    "Own-key signing only supports JAdES, not " + request.type()));
        }
        if (!OwnKeySigningConfig.ES256.equals(config.algorithm())) {
            return Mono.error(new SigningException(SigningFailureReason.UNSUPPORTED_ALGORITHM,
                    "Own-key signing only supports ES256"));
        }
        KmsSigningPort port = kmsSigningPort.getIfAvailable();
        if (port == null) {
            return Mono.error(new SigningException(SigningFailureReason.KEY_UNUSABLE,
                    "KMS signing is not enabled on this issuer"));
        }

        List<X509Certificate> chain = StoredCertificateInfo.chain(config);
        X509Certificate leaf = chain.getFirst();
        Instant now = clock.instant();
        // Trust validation of the chain is out of scope here (tech-debt 9 / EUD-264): the leaf must be a
        // valid P-256 end-entity signing certificate and the chain must link, but its anchor is not checked.
        // Each check fails with its own CertificateCheck, so the audit trail says which one failed.
        if (!SigningCertificateChecks.isValidAt(leaf, now)) {
            return now.isBefore(leaf.getNotBefore().toInstant())
                    ? Mono.error(new CertificateCheckException(CertificateCheck.NOT_YET_VALID,
                            "The stored signing certificate is not yet valid"))
                    : Mono.error(new CertificateCheckException(CertificateCheck.EXPIRED,
                            "The stored signing certificate is expired"));
        }
        if (!SigningCertificateChecks.isP256(leaf)) {
            return Mono.error(new CertificateCheckException(CertificateCheck.NOT_P256,
                    "The stored signing certificate is not a P-256 certificate"));
        }
        if (!SigningCertificateChecks.isEndEntity(leaf)) {
            return Mono.error(new CertificateCheckException(CertificateCheck.CA_CERTIFICATE,
                    "The stored signing certificate is a CA certificate"));
        }
        if (!SigningCertificateChecks.allowsSigning(leaf)) {
            return Mono.error(new CertificateCheckException(CertificateCheck.SIGNING_NOT_ALLOWED,
                    "The key usage of the stored signing certificate does not allow signing"));
        }
        if (!SigningCertificateChecks.isLinkedChain(chain, now)) {
            return Mono.error(new CertificateCheckException(CertificateCheck.CHAIN_INVALID,
                    "The stored certificate chain does not link or holds an invalid intermediate certificate"));
        }

        // Never a qualified seal, whatever the certificate declares: KMS is not a QSCD, so an own-key
        // signature is at most advanced (EUD-251 PRD §1). The certificate's own qualification is audited.
        CertificateInfo certInfo = StoredCertificateInfo.from(config, false);
        String headerJson = jadesHeaderBuilderService.buildHeader(
                certInfo, cscSigningProperties.signatureProfile(), request.typ());
        String signingInput = Base64UrlUtils.encodeUtf8(headerJson) + "." + Base64UrlUtils.encodeUtf8(request.data());
        byte[] digest = sha256(signingInput);

        return port.sign(config.kmsKeyRef(), digest)
                .map(der -> toVerifiedJws(tenant, config, leaf, signingInput, der))
                .map(jws -> new SigningResult(SigningType.JADES, jws));
    }

    private byte[] sha256(String signingInput) {
        try {
            return hashGeneratorService.sha256Digest(signingInput.getBytes(StandardCharsets.US_ASCII));
        } catch (HashGenerationException e) {
            throw new SigningException("Failed to compute the signing input digest", e);
        }
    }

    private String toVerifiedJws(String tenant, OwnKeySigningConfig config, X509Certificate leaf,
                                 String signingInput, byte[] derSignature) {
        String joseSignature;
        try {
            joseSignature = JwsSignatureEncoder.toJoseSignature(
                    Base64.getEncoder().encodeToString(derSignature), JWSAlgorithm.ES256);
        } catch (IllegalArgumentException | IllegalStateException _) {
            throw invalidSignature(tenant, config);
        }
        byte[] concat = Base64.getUrlDecoder().decode(joseSignature);
        if (!Es256SignatureVerifier.verify(signingInput, concat, leaf)) {
            throw invalidSignature(tenant, config);
        }
        return signingInput + "." + joseSignature;
    }

    private KmsSigningException invalidSignature(String tenant, OwnKeySigningConfig config) {
        log.error("invalid KMS signature tenant={} keyRef={}", tenant, KmsKeyRefs.forLog(config.kmsKeyRef()));
        return new KmsSigningException(SigningFailureReason.INVALID_RESPONSE,
                "The signature returned by KMS does not verify with the stored certificate");
    }
}
