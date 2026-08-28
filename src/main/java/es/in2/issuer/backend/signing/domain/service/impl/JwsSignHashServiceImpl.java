package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwsSignHashServiceImpl implements JwsSignHashService {

    public static final String HASH_ALGO_OID_SHA256 = "2.16.840.1.101.3.4.2.1";

    private final HashGeneratorService hashGeneratorService;
    private final CscPort cscPort;

    @Override
    public Mono<String> signJwtWithSignHash(RemoteSignatureDto cfg, String accessToken, String headerJson, String payloadJson, String signAlgoOid) {

        final String headerB64Url;
        final String payloadB64Url;

        try {
            headerB64Url = Base64UrlUtils.encodeUtf8(headerJson);
            payloadB64Url = Base64UrlUtils.encodeUtf8(payloadJson);
        } catch (Exception e) {
            return Mono.error(new RemoteSignatureException("Failed to build JWS header/payload", e));
        }

        String signingInput = headerB64Url + "." + payloadB64Url;
        byte[] signingInputBytes = signingInput.getBytes(StandardCharsets.US_ASCII);

        // The digest is encoded as base64url here (the canonical JOSE form, and
        // what the CSC v2 / DSS path expects). Per-QTSP hash encoding is the
        // adapter's responsibility: the Vintegris v1 adapter transcodes this to
        // standard Base64, which that provider requires. The hash is only the
        // transport of the digest to the QTSP and never becomes part of the
        // final JWS, so the returned signature is unaffected by the encoding.
        final String hashB64Url;
        try {
            byte[] digest = hashGeneratorService.sha256Digest(signingInputBytes);
            hashB64Url = Base64UrlUtils.encode(digest);
        } catch (Exception e) {
            return Mono.error(new RemoteSignatureException("Failed to compute signingInput digest", e));
        }

        return cscPort
                .authorizeForHash(cfg, accessToken, hashB64Url, HASH_ALGO_OID_SHA256)
                .retryWhen(signHashRetrySpec("csc.authorizeForHash"))
                .flatMap(sad ->
                        cscPort
                                .signHash(
                                        cfg,
                                        accessToken,
                                        sad,
                                        hashB64Url,
                                        HASH_ALGO_OID_SHA256,
                                        signAlgoOid
                                )
                                .retryWhen(signHashRetrySpec("csc.signHash"))
                )
                .map(signatureB64Url -> signingInput + "." + signatureB64Url)
                .doOnSuccess(jwt ->
                        log.info("signHash completed successfully. JWS length={}", jwt.length())
                )
                .doOnError(ex ->
                        log.error("signHash failed after retries. reason={}", ex.getMessage(), ex)
                );
    }

    private Retry signHashRetrySpec(String operationName) {
        return Retry.backoff(3, Duration.ofSeconds(1))
                .maxBackoff(Duration.ofSeconds(5))
                .jitter(0.5)
                .filter(QtspRetryPolicy::isRecoverable)
                .doBeforeRetry(rs -> {
                    long attempt = rs.totalRetries() + 1;
                    Throwable failure = rs.failure();
                    String msg = failure != null ? failure.getMessage() : "n/a";

                    log.warn(
                            "Retrying {}. attempt={} of 3, reason={}",
                            operationName,
                            attempt,
                            msg
                    );
                });
    }
}