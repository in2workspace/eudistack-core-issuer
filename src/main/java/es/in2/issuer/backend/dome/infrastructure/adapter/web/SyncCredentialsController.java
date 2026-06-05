package es.in2.issuer.backend.dome.infrastructure.adapter.web;

import es.in2.issuer.backend.dome.application.workflow.ResyncCredentialsWorkflow;
import es.in2.issuer.backend.dome.domain.model.sync.HolderKeyThumbprint;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyKey;
import es.in2.issuer.backend.dome.infrastructure.adapter.web.dto.SyncCredentialsRequest;
import es.in2.issuer.backend.dome.infrastructure.adapter.web.dto.SyncCredentialsResponse;
import es.in2.issuer.backend.shared.domain.util.Constants;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

/**
 * Primary adapter handling inbound HTTP request for credentials synchronization.
 * Exposes the /internal/dome/sync-credentials endpoint.
 */
@RestController
@RequestMapping(Constants.SYNC_ENDPOINT)
public class SyncCredentialsController {
    private final ResyncCredentialsWorkflow resyncCredentialsWorkflow;

    public SyncCredentialsController(ResyncCredentialsWorkflow resyncCredentialsWorkflow) {
        this.resyncCredentialsWorkflow = resyncCredentialsWorkflow;
    }

    /**
     * Handles the POST request to synchronize user credentials during the first login.
     * @param request             The validated inbound request containing the thumbprint and idempotency key.
     * @param authorizationHeader The optional Authorization header from the client.
     * @return A Mono emitting an HTTP ResponseEntity with SyncCredentialsResponse payload.
     */
    @PostMapping
    public Mono<ResponseEntity<SyncCredentialsResponse>> syncCredentials(
            @Valid @RequestBody SyncCredentialsRequest request,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {

        IdempotencyKey idempotencyKey = new IdempotencyKey(request.idempotencyKey());
        HolderKeyThumbprint thumbprint = new HolderKeyThumbprint(request.holderKeyThumbprint());

        return resyncCredentialsWorkflow.execute(Constants.TENANT_DOME, idempotencyKey, thumbprint)
                .map(workflowResult -> {
                    SyncCredentialsResponse responseBody = new SyncCredentialsResponse(
                            workflowResult.syncCredentialsResult().credentials(),
                            workflowResult.syncCredentialsResult().format()
                    );
                    ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.ok();

                    if (workflowResult.isCacheHit()) {
                        responseBuilder.header(Constants.HEADER_IDEMPOTENT_REPLAY, "true");
                    }
                    return responseBuilder.body(responseBody);
                });
    }
}
