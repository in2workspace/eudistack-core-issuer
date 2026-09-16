package es.in2.issuer.backend.shared.infrastructure.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import javax.annotation.Nullable;
import java.util.*;

@Component
@Slf4j
public class HttpUtils {

    private final WebClient webClient;

    public HttpUtils(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    public Mono<String> getRequest(@Nullable String url, List<Map.Entry<String, String>> headers) {
        logOutboundRequest("GET", url, headers, null);
        return webClient.get()
                .uri(Objects.requireNonNull(ensureUrlHasProtocol(url)))
                .headers(httpHeaders -> headers.forEach(entry -> httpHeaders.add(entry.getKey(), entry.getValue())))
                .retrieve()
                .onStatus(status -> status != HttpStatus.OK, clientResponse ->
                        clientResponse.bodyToMono(String.class)
                                .defaultIfEmpty("")
                                .doOnNext(errorBody -> logOutboundErrorResponse("GET", url, clientResponse.statusCode().value(), errorBody))
                                .map(errorBody -> new RuntimeException(
                                        "Error during get request:" + clientResponse.statusCode()
                                                + (errorBody.isBlank() ? "" : " body=" + errorBody))))
                .bodyToMono(String.class)
                .doOnNext(responseBody -> logOutboundResponse("GET", url, responseBody));
    }

    public Mono<String> postRequest(@Nullable String url, List<Map.Entry<String, String>> headers, String body) {
        logOutboundRequest("POST", url, headers, body);
        return webClient.post()
                .uri(Objects.requireNonNull(ensureUrlHasProtocol(url)))
                .headers(httpHeaders -> headers.forEach(entry -> httpHeaders.add(entry.getKey(), entry.getValue())))
                .bodyValue(body)
                .retrieve()
                .onStatus(status -> status != HttpStatus.OK, clientResponse ->
                        clientResponse.bodyToMono(String.class)
                                .defaultIfEmpty("")
                                .doOnNext(errorBody -> logOutboundErrorResponse("POST", url, clientResponse.statusCode().value(), errorBody))
                                .map(errorBody -> new RuntimeException(
                                        "Error during post request:" + clientResponse.statusCode()
                                                + (errorBody.isBlank() ? "" : " body=" + errorBody))))
                .bodyToMono(String.class)
                .doOnNext(responseBody -> logOutboundResponse("POST", url, responseBody));
    }

    /**
     * DEBUG-only, local-dev logging of the full outbound request, headers included
     * (Authorization/Basic auth values, client secrets, SAD, credential passwords).
     * Never enable {@code es.in2.issuer} at DEBUG outside a local machine: these
     * lines print secrets that must not reach shared logs (staging/prod, log
     * aggregators, CI artifacts).
     */
    private void logOutboundRequest(String method, String url, List<Map.Entry<String, String>> headers, @Nullable String body) {
        if (log.isDebugEnabled()) {
            log.debug("[SIGNING-HTTP][SENSITIVE][LOCAL-ONLY] --> {} {} headers={} body={}", method, url, headers, body);
        }
    }

    private void logOutboundResponse(String method, String url, String body) {
        if (log.isDebugEnabled()) {
            log.debug("[SIGNING-HTTP][SENSITIVE][LOCAL-ONLY] <-- {} {} body={}", method, url, body);
        }
    }

    private void logOutboundErrorResponse(String method, String url, int status, String body) {
        if (log.isDebugEnabled()) {
            log.debug("[SIGNING-HTTP][SENSITIVE][LOCAL-ONLY] <-- {} {} status={} body={}", method, url, status, body);
        }
    }

    public Mono<List<Map.Entry<String, String>>> prepareHeadersWithAuth(String token) {
        return Mono.fromCallable(() -> {
            List<Map.Entry<String, String>> headers = new ArrayList<>();
            headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + token));
            return headers;
        });
    }

    public static String ensureUrlHasProtocol(String url) {
        if (url == null) {
            return null;
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return "https://" + url;
        }
        return url;
    }

}
