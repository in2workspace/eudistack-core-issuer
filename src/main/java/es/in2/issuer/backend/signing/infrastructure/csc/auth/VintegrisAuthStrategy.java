package es.in2.issuer.backend.signing.infrastructure.csc.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.exception.AccessTokenException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

@Slf4j
@Component
public class VintegrisAuthStrategy implements CscAuthStrategy {

    private static final String AUTHORIZE_PATH = "/trustedapps/v1/trusted/app/authorize";
    private static final String SIMPLE_TOKEN_PATH = "/trustedapps/v1/trusted/app/login/first";
    private static final String ROBUST_TOKEN_PATH = "/trustedapps/v1/trusted/app/login/second";

    private final ObjectMapper objectMapper;
    private final WebClient webClient;

    public VintegrisAuthStrategy(
            ObjectMapper objectMapper,
            @Qualifier("commonWebClient") WebClient webClient
    ) {
        this.objectMapper = objectMapper;
        this.webClient = webClient;
    }

    @Override
    public CscAuthProvider supportedProvider() {
        return CscAuthProvider.VINTEGRIS;
    }

    @Override
    public Mono<String> requestAccessToken(SigningRequest request, String scope, boolean unused) {
        RemoteSignatureDto cfg = request.remoteSignature();
        return Mono.fromCallable(() -> buildJwt(cfg))
                .flatMap(jwt -> authorizeApp(cfg, jwt))
                .flatMap(appToken -> fetchSimpleToken(cfg, appToken)
                        .flatMap(simpleToken -> fetchRobustToken(cfg, appToken, simpleToken)))
                .onErrorMap(
                        e -> !(e instanceof AccessTokenException),
                        e -> new AccessTokenException("Vintegris auth failed: " + e.getMessage(), e));
    }

    private String buildJwt(RemoteSignatureDto cfg) throws Exception {
        Map<String, String> header = new LinkedHashMap<>();
        header.put("typ", "JWT");
        header.put("alg", "HS256");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", cfg.qtspTenantId());
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("iss", cfg.applicationName());
        payload.put("azp", cfg.appId());

        String encodedHeader = base64UrlEncode(objectMapper.writeValueAsBytes(header));
        String encodedPayload = base64UrlEncode(objectMapper.writeValueAsBytes(payload));
        String signingInput = encodedHeader + "." + encodedPayload;
        String encodedSignature = base64UrlEncode(hmacSha256(signingInput, sha256(cfg.accessKey())));
        return signingInput + "." + encodedSignature;
    }

    private Mono<String> authorizeApp(RemoteSignatureDto cfg, String jwt) {
        logSensitiveRequest("POST", cfg.authUrl() + AUTHORIZE_PATH, "Authorization", jwt, null);
        return webClient.post()
                .uri(cfg.authUrl() + AUTHORIZE_PATH)
                .header("Authorization", jwt)
                .retrieve()
                .bodyToMono(TrustedAppActivationResponse.class)
                .map(r -> r.content().authorization())
                .doOnNext(appToken -> logSensitiveResponse(cfg.authUrl() + AUTHORIZE_PATH, "authorization=" + appToken))
                .doOnError(e -> log.error("Vintegris trusted app authorization failed", e));
    }

    private Mono<String> fetchSimpleToken(RemoteSignatureDto cfg, String appToken) {
        String encodedUsername = Base64.getEncoder()
                .encodeToString(cfg.managerId().getBytes(StandardCharsets.UTF_8));
        String uri = cfg.authUrl() + SIMPLE_TOKEN_PATH + "?username=" + encodedUsername;
        logSensitiveRequest("POST", uri, "Application", appToken, null);
        return webClient.post()
                .uri(uri)
                .header("Application", appToken)
                .retrieve()
                .bodyToMono(SimpleTokenResponse.class)
                .map(r -> r.content().token())
                .doOnNext(simpleToken -> logSensitiveResponse(uri, "token=" + simpleToken))
                .doOnError(e -> log.error("Vintegris simple token fetch failed", e));
    }

    /**
     * Exchanges the simple token for a robust token via {@code login/second}.
     * The CSC signing operations ({@code credentials/authorize},
     * {@code signatures/signHash}) require this robust token; the simple token
     * alone yields a 400 on authorize. Both the simple token (Authorization)
     * and the app token (Application) are sent as {@code Bearer} credentials.
     */
    private Mono<String> fetchRobustToken(RemoteSignatureDto cfg, String appToken, String simpleToken) {
        String uri = cfg.authUrl() + ROBUST_TOKEN_PATH;
        logSensitiveRequest("POST", uri, "Authorization=Bearer " + simpleToken, "Application=Bearer " + appToken, null);
        return webClient.post()
                .uri(uri)
                .header("Authorization", "Bearer " + simpleToken)
                .header("Application", "Bearer " + appToken)
                .retrieve()
                .bodyToMono(SimpleTokenResponse.class)
                .map(r -> r.content().token())
                .doOnNext(robustToken -> logSensitiveResponse(uri, "token=" + robustToken))
                .doOnError(e -> log.error("Vintegris robust token fetch failed", e));
    }

    /**
     * DEBUG-only, local-dev logging of the full outbound request, including the
     * signed JWT / bearer tokens sent as headers. Never enable {@code es.in2.issuer}
     * at DEBUG outside a local machine: these lines print secrets that must not
     * reach shared logs (staging/prod, log aggregators, CI artifacts).
     */
    private void logSensitiveRequest(String method, String url, String header1, String header2, @Nullable String body) {
        if (log.isDebugEnabled()) {
            log.debug("[SIGNING-HTTP][SENSITIVE][LOCAL-ONLY] --> {} {} {} {} body={}", method, url, header1, header2, body);
        }
    }

    private void logSensitiveResponse(String url, String body) {
        if (log.isDebugEnabled()) {
            log.debug("[SIGNING-HTTP][SENSITIVE][LOCAL-ONLY] <-- {} body={}", url, body);
        }
    }

    private byte[] sha256(String value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] hmacSha256(String data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private record TrustedAppActivationResponse(Content content) {
        record Content(String authorization) {}
    }

    private record SimpleTokenResponse(Content content) {
        record Content(String token) {}
    }
}
