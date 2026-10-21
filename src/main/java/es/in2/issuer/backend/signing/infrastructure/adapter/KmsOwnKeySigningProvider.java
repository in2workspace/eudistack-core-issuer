package es.in2.issuer.backend.signing.infrastructure.adapter;

import com.nimbusds.jose.JWSAlgorithm;
import es.in2.issuer.backend.signing.domain.exception.HashGenerationException;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import es.in2.issuer.backend.signing.domain.util.Es256SignatureVerifier;
import es.in2.issuer.backend.signing.domain.util.JwsSignatureEncoder;
import es.in2.issuer.backend.signing.domain.util.SigningCertificateChecks;
import es.in2.issuer.backend.signing.domain.util.StoredCertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.CertificateQualificationUtils;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Base64;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Signs a JAdES JWS with the tenant's own ES256 key held in KMS (EUD-289).
 *
 * <p>It does not implement {@link es.in2.issuer.backend.signing.domain.spi.SigningProvider}: that
 * interface is keyed by the CSC operation ({@code CscSignType}) and resolved from the QTSP
 * configuration, whereas this provider is selected by the tenant's signing modality and takes the
 * own-key configuration explicitly. {@code DelegatingSigningProviderImpl} chooses between the two.
 *
 * <p>No user token is used: the KMS authorizes with the issuer's runtime role (AC-04).
 * The returned signature is always verified against the stored leaf certificate first, so a
 * signature the credential's {@code x5c} could not validate is never returned (AC-11).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KmsOwnKeySigningProvider {

    private static final String UNKNOWN_TENANT = "unknown";

    /** The port exists only when {@code issuer.signing.kms.enabled=true}. */
    private final ObjectProvider<KmsSigningPort> kmsSigningPort;
    private final JadesHeaderBuilderService jadesHeaderBuilderService;
    private final HashGeneratorService hashGeneratorService;
    private final CscSigningProperties cscSigningProperties;
    private final Clock clock;

    public Mono<SigningResult> sign(SigningRequest request, OwnKeySigningConfig config) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, UNKNOWN_TENANT);
            return signAs(tenant, request, config);
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

        X509Certificate leaf = StoredCertificateInfo.leaf(config);
        // Trust validation of the chain is out of scope here (tech-debt 9 / EUD-264): only the
        // validity window and the key type of the leaf are checked.
        if (!SigningCertificateChecks.isValidAt(leaf, clock.instant()) || !SigningCertificateChecks.isP256(leaf)) {
            return Mono.error(new SigningException(SigningFailureReason.CERTIFICATE_INVALID,
                    "The stored signing certificate is expired, not yet valid or not a P-256 certificate"));
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
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw invalidSignature(tenant, config);
        }
        byte[] concat = Base64.getUrlDecoder().decode(joseSignature);
        if (!Es256SignatureVerifier.verify(signingInput, concat, leaf)) {
            throw invalidSignature(tenant, config);
        }
        return signingInput + "." + joseSignature;
    }

    private KmsSigningException invalidSignature(String tenant, OwnKeySigningConfig config) {
        log.error("invalid KMS signature tenant={} keyRef={}", tenant, config.kmsKeyRef());
        return new KmsSigningException(SigningFailureReason.INVALID_RESPONSE,
                "The signature returned by KMS does not verify with the stored certificate");
    }
}
