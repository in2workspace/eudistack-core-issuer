package es.in2.issuer.backend.dome.infrastructure.adapter.web;

import es.in2.issuer.backend.dome.application.workflow.ResyncCredentialsWorkflow;
import es.in2.issuer.backend.dome.domain.model.sync.HolderKeyThumbprint;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyKey;
import es.in2.issuer.backend.dome.infrastructure.adapter.web.dto.SyncCredentialsRequest;
import es.in2.issuer.backend.dome.infrastructure.adapter.web.dto.SyncCredentialsResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/internal/dome/sync-credentials")
public class SyncCredentialsController {
    private final ResyncCredentialsWorkflow resyncCredentialsWorkflow;

    public SyncCredentialsController(ResyncCredentialsWorkflow resyncCredentialsWorkflow) {
        this.resyncCredentialsWorkflow = resyncCredentialsWorkflow;
    }

    @PostMapping
    public Mono<ResponseEntity<SyncCredentialsResponse>> syncCredentials(
            @Valid @RequestBody SyncCredentialsRequest request,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {

        String tenant = "dome";
        IdempotencyKey idempotencyKey = new IdempotencyKey(request.idempotencyKey());
        HolderKeyThumbprint thumbprint = new HolderKeyThumbprint(request.holderKeyThumbprint());

        return resyncCredentialsWorkflow.execute(tenant, idempotencyKey, thumbprint)
                .map(workflowResult -> {
                    SyncCredentialsResponse responseBody = new SyncCredentialsResponse(
                            workflowResult.syncCredentialsResult().credentials(),
                            workflowResult.syncCredentialsResult().format()
                    );
                    ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.ok();

                    if (workflowResult.isCacheHit()) {
                        responseBuilder.header("Idempotent-Replay", "true");
                    }
                    return responseBuilder.body(responseBody);
                });
    }
}
