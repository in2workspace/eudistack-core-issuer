package es.in2.issuer.backend.signing.infrastructure.csc.v1;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.infrastructure.util.HttpUtils;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.infrastructure.csc.CscApiVersion;
import es.in2.issuer.backend.signing.infrastructure.csc.auth.CscAuthStrategyResolver;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.infrastructure.csc.v1.dto.*;
import es.in2.issuer.backend.signing.infrastructure.csc.v1.mapper.CscV1CertificateInfoMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.AbstractMap;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class CscV1Adapter implements CscPort {

    private static final String CHAIN = "chain";
    private final CscAuthStrategyResolver authResolver;
    private final CscV1CertificateInfoMapper certificateInfoMapper;
    private final ObjectMapper objectMapper;
    private final HttpUtils httpUtils;

    @Override
    public String supportedVersion() {
        return CscApiVersion.V1.getValue();
    }

    @Override
    public Mono<String> requestAccessToken(RemoteSignatureDto cfg, String scope, boolean includeAuthDetails, String credentialData) {
        SigningRequest bridgeRequest = SigningRequest.builder()
                .remoteSignature(cfg)
                .data(credentialData)
                .build();
        return authResolver
                .resolveFromValue(cfg.provider())
                .requestAccessToken(bridgeRequest, scope, includeAuthDetails);
    }

    @Override
    public Mono<CertificateInfo> getCredentialInfo(RemoteSignatureDto cfg, String accessToken, String credentialId) {
        CscV1CredentialsInfoRequest body = new CscV1CredentialsInfoRequest(credentialId, CHAIN, true, true);
        return post(cfg.url() + CscV1Paths.INFO, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> {
                    Map<String, Object> map = objectMapper.readValue(json, new TypeReference<>() {});
                    return certificateInfoMapper.map(map);
                }))
                .onErrorMap(e -> !(e instanceof RemoteSignatureException),
                        e -> new RemoteSignatureException("Failed to fetch credentials/info: " + e.getMessage(), e));
    }

    @Override
    public Mono<Boolean> validateCredentialId(RemoteSignatureDto cfg, String accessToken, String credentialId) {
        CscV1CredentialsListRequest body = new CscV1CredentialsListRequest(credentialId);

        String url = cfg.url() + CscV1Paths.LIST;
        return post(url, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> {
                    CscV1CredentialsListResponse resp = objectMapper.readValue(json, CscV1CredentialsListResponse.class);
                    List<String> ids = resp.credentialIds();
                    return ids != null && ids.stream().anyMatch(id -> id.trim().equalsIgnoreCase(credentialId.trim()));
                }))
                .switchIfEmpty(Mono.just(false))
                .onErrorMap(e -> !(e instanceof RemoteSignatureException),
                        e -> new RemoteSignatureException("Failed to list credentials from url: " + url + " " + e.getMessage(), e));
    }

    @Override
    public Mono<List<String>> listCredentialIds(RemoteSignatureDto cfg, String accessToken) {
        CscV1CredentialsListRequest body = new CscV1CredentialsListRequest(null);
        return post(cfg.url() + CscV1Paths.LIST, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> {
                    CscV1CredentialsListResponse resp = objectMapper.readValue(json, CscV1CredentialsListResponse.class);
                    return resp.credentialIds() != null ? resp.credentialIds() : List.<String>of();
                }))
                .onErrorMap(e -> !(e instanceof RemoteSignatureException),
                        e -> new RemoteSignatureException("Failed to list credentials: " + e.getMessage(), e));
    }

    @Override
    public Mono<String> authorizeForHash(RemoteSignatureDto cfg, String accessToken, String hashB64Url, String hashAlgoOid) {
        CscV1AuthorizeRequest body = new CscV1AuthorizeRequest(
                cfg.credentialId(),
                1,
                List.of(toStandardBase64(hashB64Url))
        );
        return post(cfg.url() + CscV1Paths.AUTHORIZE, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> objectMapper.readValue(json, CscV1AuthorizeResponse.class)))
                .flatMap(resp -> {
                    if (resp.sad() == null || resp.sad().isBlank()) {
                        return Mono.error(new RemoteSignatureException("Empty authorize response (missing SAD)"));
                    }
                    return Mono.just(resp.sad());
                })
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized on credentials/authorize (hash)"));
                    }
                    return Mono.error(new RemoteSignatureException("CSC v1 authorize(hash) failed", ex));
                });
    }

    @Override
    public Mono<String> signHash(RemoteSignatureDto cfg, String accessToken, String sad, String hashB64Url, String hashAlgoOid, String signAlgoOid) {
        CscV1SignHashRequest body = new CscV1SignHashRequest(
                cfg.credentialId(),
                sad,
                List.of(toStandardBase64(hashB64Url)),
                hashAlgoOid,
                signAlgoOid
        );
        return post(cfg.url() + CscV1Paths.SIGN_HASH, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> objectMapper.readValue(json, CscV1SignHashResponse.class)))
                .flatMap(resp -> {
                    if (resp.signatures() == null || resp.signatures().isEmpty() || resp.signatures().getFirst() == null) {
                        return Mono.error(new RemoteSignatureException("signHash response missing signatures[0]"));
                    }
                    return Mono.just(resp.signatures().getFirst());
                })
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized on signatures/signHash"));
                    }
                    return Mono.error(new RemoteSignatureException("CSC v1 signHash failed", ex));
                });
    }

    @Override
    public Mono<String> authorizeForDoc(RemoteSignatureDto cfg, String accessToken) {
        return Mono.error(new RemoteSignatureException("authorizeForDoc not supported in CSC v1"));
    }

    @Override
    public Mono<String> signDoc(RemoteSignatureDto cfg, String accessToken, String sad, String docB64, String signAlgoOid) {
        return Mono.error(new RemoteSignatureException("signDoc not supported in CSC v1"));
    }

    private Mono<String> post(String url, String accessToken, Object body) {
        String json;
        try {
            json = objectMapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException("Error serializing CSC v1 request body", e));
        }

        List<Map.Entry<String, String>> headers = List.of(
                new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken),
                new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
        );

        return httpUtils.postRequest(url, headers, json);
    }

    /**
     * Vintegris (CSC v1) requires the {@code hash} parameter as standard Base64
     * (RFC 4648, with padding); a base64url value is rejected with
     * {@code 400 "Invalid parameter 'hash'"}. The shared signing service emits
     * base64url, so transcode here. Same digest bytes, different alphabet — the
     * resulting signature is unaffected.
     */
    private static String toStandardBase64(String hashB64Url) {
        return Base64.getEncoder().encodeToString(Base64.getUrlDecoder().decode(hashB64Url));
    }
}
