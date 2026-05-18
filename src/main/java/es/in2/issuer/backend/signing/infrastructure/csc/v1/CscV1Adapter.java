package es.in2.issuer.backend.signing.infrastructure.csc.v1;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.infrastructure.util.HttpUtils;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.infrastructure.csc.CscApiVersion;
import es.in2.issuer.backend.signing.infrastructure.csc.v1.dto.*;
import es.in2.issuer.backend.signing.infrastructure.csc.v1.mapper.CscV1CertificateInfoMapper;
import es.in2.issuer.backend.signing.infrastructure.csc.auth.CscAuthStrategyResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.AbstractMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class CscV1Adapter implements CscPort {

    private final CscAuthStrategyResolver authResolver;
    private final CscV1CertificateInfoMapper certificateInfoMapper;
    private final ObjectMapper objectMapper;
    private final HttpUtils httpUtils;

    public CscApiVersion supportedVersion() {
        return CscApiVersion.V1;
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
        CscV1CredentialsInfoRequest body = new CscV1CredentialsInfoRequest(credentialId, "chain", true, true);
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
        CscV1CredentialsListRequest body = new CscV1CredentialsListRequest(true, "chain", true, true, true, 0, "string");
        return post(cfg.url() + CscV1Paths.LIST, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> {
                    CscV1CredentialsListResponse resp = objectMapper.readValue(json, CscV1CredentialsListResponse.class);
                    List<String> ids = resp.credentialIds();
                    return ids != null && ids.stream().anyMatch(id -> id.trim().equalsIgnoreCase(credentialId.trim()));
                }))
                .switchIfEmpty(Mono.just(false))
                .onErrorMap(e -> !(e instanceof RemoteSignatureException),
                        e -> new RemoteSignatureException("Failed to list credentials: " + e.getMessage(), e));
    }

    @Override
    public Mono<List<String>> listCredentialIds(RemoteSignatureDto cfg, String accessToken) {
        CscV1CredentialsListRequest body = new CscV1CredentialsListRequest(true, "chain", true, true, true, 0, "string");
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
                List.of(hashB64Url),
                hashAlgoOid,
                List.of(Map.of("id", "password", "value", cfg.credentialPassword()))
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
                List.of(hashB64Url),
                hashAlgoOid,
                signAlgoOid
        );
        return post(cfg.url() + CscV1Paths.SIGN_HASH, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> objectMapper.readValue(json, CscV1SignHashResponse.class)))
                .flatMap(resp -> {
                    if (resp.signatures() == null || resp.signatures().isEmpty() || resp.signatures().get(0) == null) {
                        return Mono.error(new RemoteSignatureException("signHash response missing signatures[0]"));
                    }
                    return Mono.just(resp.signatures().get(0));
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
        CscV1AuthorizeRequest body = new CscV1AuthorizeRequest(
                cfg.credentialId(),
                1,
                null,
                null,
                List.of(Map.of("id", "password", "value", cfg.credentialPassword()))
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
                        return Mono.error(new RemoteSignatureException("Unauthorized on credentials/authorize (doc)"));
                    }
                    return Mono.error(new RemoteSignatureException("CSC v1 authorize(doc) failed", ex));
                });
    }

    @Override
    public Mono<String> signDoc(RemoteSignatureDto cfg, String accessToken, String sad, String docB64, String signAlgoOid) {
        CscV1SignDocRequest body = new CscV1SignDocRequest(
                cfg.credentialId(),
                sad,
                "eu_eidas_aesealqc",
                List.of(Map.of(
                        "document", docB64,
                        "signature_format", "J",
                        "conformance_level", "Ades-B",
                        "signAlgo", signAlgoOid
                ))
        );
        return post(cfg.url() + CscV1Paths.SIGN_DOC, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> {
                    CscV1SignDocResponse resp = objectMapper.readValue(json, CscV1SignDocResponse.class);
                    if (resp.documentWithSignature() == null || resp.documentWithSignature().isEmpty()) {
                        throw new RemoteSignatureException("signDoc response missing DocumentWithSignature");
                    }
                    return resp.documentWithSignature().get(0);
                }))
                .doOnError(error -> log.error("Error in signDoc: {}", error.getMessage()));
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
}
