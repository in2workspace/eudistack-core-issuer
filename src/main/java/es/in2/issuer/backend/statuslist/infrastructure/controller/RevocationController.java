package es.in2.issuer.backend.statuslist.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.dto.RevokeIssuanceRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebInputException;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;

/**
 * The revocation contract shared by operators and systems (EUD-247). The status list context owns
 * revocation; the path is the contract's, under the issuance process it revokes.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping(ISSUANCES_PATH)
public class RevocationController {

    private final RevocationWorkflow revocationWorkflow;
    private final UrlResolver urlResolver;

    /**
     * The body is read here rather than bound by the framework so that an absent or unreadable one
     * reaches the workflow like a missing reason: answered with its violation, and traced.
     */
    @PostMapping("/{id}/revocation")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> revokeIssuance(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken,
            @PathVariable("id") String id,
            @RequestBody(required = false) Mono<RevokeIssuanceRequest> request,
            ServerWebExchange exchange
    ) {
        String processId = UUID.randomUUID().toString();
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);

        return request
                .mapNotNull(RevokeIssuanceRequest::reason)
                .onErrorResume(ServerWebInputException.class, e -> Mono.empty())
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(reason -> revocationWorkflow.revokeIssuance(
                        processId, bearerToken, id, reason.orElse(null), publicIssuerBaseUrl));
    }
}
