package es.in2.issuer.backend.signing.infrastructure.qtsp.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.exception.AccessTokenException;
import es.in2.issuer.backend.signing.infrastructure.model.QtspProvider;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.spi.QtspAuthPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

@Slf4j
public class VintegrisAuthClient implements QtspAuthPort {

    private static final String AUTHORIZE_PATH = "/trustedapps/v1/trusted/app/authorize";
    private static final String SIMPLE_TOKEN_PATH = "/trustedapps/v1/trusted/app/login/first";

    private final ObjectMapper objectMapper;
    private final WebClient webClient;

    public VintegrisAuthClient(
            ObjectMapper objectMapper,
            @Qualifier("commonWebClient") WebClient webClient
    ) {
        this.objectMapper = objectMapper;
        this.webClient = webClient;
    }

    @Override
    public QtspProvider supportedProvider() {
        return QtspProvider.VINTEGRIS;
    }

    @Override
    public Mono<String> requestAccessToken(SigningRequest request, String scope, boolean unused) {
        RemoteSignatureDto cfg = remoteCfgRequired(request);
        return Mono.fromCallable(() -> buildJwt(cfg))
                .flatMap(jwt -> authorizeApp(cfg, jwt))
                .flatMap(appToken -> fetchSimpleToken(cfg, appToken))
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
        return webClient.post()
                .uri(cfg.url() + AUTHORIZE_PATH)
                .header("Authorization", jwt)
                .retrieve()
                .bodyToMono(TrustedAppActivationResponse.class)
                .map(r -> r.content().authorization())
                .doOnNext(t -> log.debug("Vintegris trusted app authorized"))
                .doOnError(e -> log.error("Vintegris trusted app authorization failed", e));
    }

    private Mono<String> fetchSimpleToken(RemoteSignatureDto cfg, String appToken) {
        String encodedUsername = Base64.getEncoder()
                .encodeToString(cfg.managerId().getBytes(StandardCharsets.UTF_8));
        return webClient.post()
                .uri(cfg.url() + SIMPLE_TOKEN_PATH + "?username=" + encodedUsername)
                .header("Application", appToken)
                .retrieve()
                .bodyToMono(SimpleTokenResponse.class)
                .map(r -> r.content().token())
                .doOnNext(t -> log.debug("Vintegris simple token acquired"))
                .doOnError(e -> log.error("Vintegris simple token fetch failed", e));
    }

    private static RemoteSignatureDto remoteCfgRequired(SigningRequest request) {
        if (request == null || request.remoteSignature() == null) {
            throw new IllegalStateException(
                    "SigningRequest.remoteSignature is null — tenant QTSP config must be resolved " +
                            "from tenant_signing_config before calling VintegrisAuthClient.");
        }
        return request.remoteSignature();
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
        record Content(String authorization) {
        }
    }

    private record SimpleTokenResponse(Content content) {
        record Content(String token) {
        }
    }
}
