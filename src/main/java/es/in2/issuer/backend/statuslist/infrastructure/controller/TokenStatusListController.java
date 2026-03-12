package es.in2.issuer.backend.statuslist.infrastructure.controller;

import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.TOKEN_STATUS_LIST_BASE;

/**
 * Serves Token Status List JWTs (draft-ietf-oauth-status-list).
 * Content-Type: application/statuslist+jwt
 */
@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping(TOKEN_STATUS_LIST_BASE)
public class TokenStatusListController {

    private static final String STATUSLIST_JWT_VALUE = "application/statuslist+jwt";
    private static final MediaType STATUSLIST_JWT = MediaType.parseMediaType(STATUSLIST_JWT_VALUE);

    private final StatusListWorkflow statusListWorkflow;

    @GetMapping(value = "/{listId}", produces = STATUSLIST_JWT_VALUE)
    public Mono<ResponseEntity<String>> getTokenStatusList(@PathVariable Long listId) {
        String processId = UUID.randomUUID().toString();

        return statusListWorkflow.getSignedStatusListCredential(listId)
                .doFirst(() -> log.info("processId={} action=getTokenStatusList step=START listId={}", processId, listId))
                .doOnSuccess(v -> log.info("processId={} action=getTokenStatusList status=completed listId={}", processId, listId))
                .doOnError(e -> log.warn("processId={} action=getTokenStatusList status=failed listId={} error={}", processId, listId, e.toString()))
                .map(jwt -> ResponseEntity.ok().contentType(STATUSLIST_JWT).body(jwt));
    }
}
