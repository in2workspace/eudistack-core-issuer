package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.signing.domain.exception.SignatureProcessingException;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.service.SignDocService;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.domain.util.JwtUtils;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import static es.in2.issuer.backend.shared.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;

@Slf4j
@Service
@RequiredArgsConstructor
public class SignDocServiceImpl implements SignDocService {

    private static final String SIGN_ALGO_OID = "OID_sign_algorithm";

    private final CscPort cscPort;
    private final JwtUtils jwtUtils;

    @Override
    public Mono<SigningResult> signIssuedCredential(SigningRequest signingRequest, String issuanceId) {
        log.debug("SignDocServiceImpl - signIssuedCredential, issuanceId: {}", issuanceId);
        return signWithRetry(signingRequest, "signIssuedCredential")
                .doOnSuccess(_ -> log.info("Successfully signed credential for issuanceId: {}", issuanceId));
    }

    @Override
    public Mono<SigningResult> signSystemCredential(SigningRequest signingRequest) {
        log.debug("SignDocServiceImpl - signSystemCredential");
        return signWithRetry(signingRequest, "signSystemCredential");
    }

    private Mono<SigningResult> signWithRetry(SigningRequest request, String operationName) {
        return Mono.defer(() -> executeSigningFlow(request))
                .doOnSuccess(result -> log.info("Remote signing succeeded ({}). resultLength={}", operationName,
                        result != null && result.data() != null ? result.data().length() : 0))
                .retryWhen(
                        Retry.backoff(3, Duration.ofSeconds(1))
                                .maxBackoff(Duration.ofSeconds(5))
                                .jitter(0.5)
                                .filter(QtspRetryPolicy::isRecoverable)
                                .doBeforeRetry(rs -> log.warn("Retrying remote signing ({}). attempt={} of 3, reason={}",
                                        operationName, rs.totalRetries() + 1,
                                        rs.failure() != null ? rs.failure().getMessage() : "n/a"))
                )
                .doOnError(ex -> log.error("Remote signing failed after retries ({}). reason={}", operationName, ex.getMessage(), ex));
    }

    private Mono<SigningResult> executeSigningFlow(SigningRequest request) {
        RemoteSignatureDto cfg = request.remoteSignature();
        String docB64 = Base64.getEncoder().encodeToString(request.data().getBytes(StandardCharsets.UTF_8));

        return cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, true, request.data())
                .flatMap(accessToken -> cscPort.authorizeForDoc(cfg, accessToken)
                        .flatMap(sad -> cscPort.signDoc(cfg, accessToken, sad, docB64, SIGN_ALGO_OID))
                )
                .flatMap(signedDocB64 -> verifyAndBuild(request, signedDocB64));
    }

    private Mono<SigningResult> verifyAndBuild(SigningRequest request, String signedDocB64) {
        return Mono.fromCallable(() -> {
            String signedDoc = new String(Base64.getDecoder().decode(signedDocB64), StandardCharsets.UTF_8);
            String receivedPayload = jwtUtils.decodePayload(signedDoc);
            if (!jwtUtils.areJsonsEqual(receivedPayload, request.data())) {
                throw new SignatureProcessingException("Signed payload received does not match the original data");
            }
            return new SigningResult(request.type(), signedDoc);
        });
    }
}
