package es.in2.issuer.backend.signing.infrastructure.adapter;

import com.nimbusds.jose.JWSAlgorithm;
import es.in2.issuer.backend.signing.domain.exception.HashGenerationException;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningProviderType;
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
import es.in2.issuer.backend.signing.infrastructure.csc.CertificateQualificationUtils;
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
 * Signs a JAdES JWS with the tenant's own ES256 key held in KMS (EUD-289).
 *
 * <p>Registered in {@code SigningProviderResolver} as {@link SigningProviderType#AWS_KMS}, next to the
 * CSC providers. {@code DelegatingSigningProviderImpl} resolves it for the own-key modality and puts
 * the tenant's own-key configuration in {@link SigningRequest#ownKey()}.
 *
 * <p>No user token is used: the KMS authorizes with the issuer's runtime role (AC-04).
 * The returned signature is always verified against the stored leaf certificate first, so a
 * signature the credential's {@code x5c} could not validate is never returned (AC-11).
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
    public SigningProviderType supportedProvider() {
        return SigningProviderType.AWS_KMS;
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
        if (!isKeyTaggedFor(tenant, config)) {
            return Mono.error(new SigningException(SigningFailureReason.NO_CONFIGURATION,
                    "The KMS key of this tenant is not tagged for it"));
        }

        List<X509Certificate> chain = StoredCertificateInfo.chain(config);
        X509Certificate leaf = chain.getFirst();
        Instant now = clock.instant();
        // Trust validation of the chain is out of scope here (tech-debt 9 / EUD-264): the leaf must be a
        // valid P-256 end-entity signing certificate and the chain must link, but its anchor is not checked.
        if (!SigningCertificateChecks.isValidAt(leaf, now) || !SigningCertificateChecks.isP256(leaf)) {
            return Mono.error(new SigningException(SigningFailureReason.CERTIFICATE_INVALID,
                    "The stored signing certificate is expired, not yet valid or not a P-256 certificate"));
        }
        if (!SigningCertificateChecks.isEndEntity(leaf) || !SigningCertificateChecks.allowsSigning(leaf)) {
            return Mono.error(new SigningException(SigningFailureReason.CERTIFICATE_INVALID,
                    "The stored signing certificate is a CA certificate or its key usage does not allow signing"));
        }
        if (!SigningCertificateChecks.isLinkedChain(chain, now)) {
            return Mono.error(new SigningException(SigningFailureReason.CERTIFICATE_INVALID,
                    "The stored certificate chain does not link or holds an invalid intermediate certificate"));
        }

        CertificateInfo certInfo = StoredCertificateInfo.from(config,
                CertificateQualificationUtils.isQualifiedSeal(config.certificateChain()));
        String headerJson = jadesHeaderBuilderService.buildHeader(
                certInfo, cscSigningProperties.signatureProfile(), request.typ());
        String signingInput = Base64UrlUtils.encodeUtf8(headerJson) + "." + Base64UrlUtils.encodeUtf8(request.data());
        byte[] digest = sha256(signingInput);

        return port.sign(config.kmsKeyRef(), digest)
                .map(der -> toVerifiedJws(tenant, config, leaf, signingInput, der))
                .map(jws -> new SigningResult(SigningType.JADES, jws));
    }

    /**
     * The key must carry the tag {@code Tenant=<tenant>} of the tenant of the request. The tenant comes
     * from the request context, never from the configuration row: a row that points to another
     * tenant's key is the case this check exists for. The tag was read when the configuration was
     * loaded, so nothing is asked to KMS here. A key that is not tagged for the tenant is reported
     * outward as {@code NO_CONFIGURATION}; {@code KEY_TENANT_MISMATCH} is only the literal of the log
     * line, so operations can alert on it, and it never triggers the reload that a disabled key does.
     *
     * <p>Limit: this is an Issuer-side check. It does not protect against a compromised Issuer
     * process, which could sign with any key its runtime role allows. Enforcing it in IAM (a session
     * tag per tenant and a condition on {@code kms:Sign}) is a later phase.
     */
    private static boolean isKeyTaggedFor(String tenant, OwnKeySigningConfig config) {
        if (tenant.equals(config.keyTenantTag())) {
            return true;
        }
        log.error("KEY_TENANT_MISMATCH tenant={} keyRef={} keyTenantTag={}", tenant,
                KmsKeyRefs.forLog(config.kmsKeyRef()),
                config.keyTenantTag() == null ? "missing" : config.keyTenantTag());
        return false;
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
