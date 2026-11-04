package es.in2.issuer.backend.statuslist.infrastructure.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.infrastructure.config.security.AuthenticationRejectionListener;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;

/**
 * Traces a revocation the security chain rejects with a 401 (EUD-247 AC-10: any request, accepted or
 * rejected). Nothing in such a request is verified, so the token is never read for an identity: the
 * trace names the requester as anonymous, with the address it came from and the reason it sent.
 */
@Component
@RequiredArgsConstructor
public class RevocationAuthenticationAuditor implements AuthenticationRejectionListener {

    private static final PathPattern ROUTE = PathPatternParser.defaultInstance.parse(ISSUANCES_PATH + "/{id}/revocation");
    /** A reason of 280 characters fits many times over; a client without a token gets no more than this read. */
    private static final int MAX_BODY_BYTES = 8 * 1024;
    private static final Duration BODY_READ_TIMEOUT = Duration.ofSeconds(2);
    private static final String REASON_FIELD = "reason";

    private final RevocationWorkflow revocationWorkflow;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> onRejected(ServerWebExchange exchange, String errorType) {
        ServerHttpRequest request = exchange.getRequest();
        if (!HttpMethod.POST.equals(request.getMethod())) {
            return Mono.empty();
        }
        PathPattern.PathMatchInfo route = ROUTE.matchAndExtract(request.getPath().pathWithinApplication());
        if (route == null) {
            return Mono.empty();
        }
        String issuanceId = route.getUriVariables().get("id");
        return readReason(request)
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .doOnNext(reason -> revocationWorkflow.traceUnauthenticated(
                        issuanceId, reason.orElse(null), errorType, clientAddress(request)))
                .then();
    }

    /** Empty when there is no body, it is too long, slow or unreadable, or the reason is not a string. */
    private Mono<String> readReason(ServerHttpRequest request) {
        return DataBufferUtils.join(request.getBody(), MAX_BODY_BYTES)
                .map(buffer -> {
                    try {
                        byte[] bytes = new byte[buffer.readableByteCount()];
                        buffer.read(bytes);
                        return bytes;
                    } finally {
                        DataBufferUtils.release(buffer);
                    }
                })
                .flatMap(bytes -> Mono.justOrEmpty(reasonOf(bytes)))
                .timeout(BODY_READ_TIMEOUT)
                .onErrorResume(e -> Mono.empty());
    }

    private Optional<String> reasonOf(byte[] body) {
        try {
            JsonNode reason = objectMapper.readTree(body).path(REASON_FIELD);
            return reason.isTextual() ? Optional.of(reason.textValue()) : Optional.empty();
        } catch (IOException | RuntimeException _) {
            return Optional.empty();
        }
    }

    private static String clientAddress(ServerHttpRequest request) {
        InetSocketAddress address = request.getRemoteAddress();
        if (address == null) {
            return "";
        }
        return address.getAddress() != null ? address.getAddress().getHostAddress() : address.getHostString();
    }
}
