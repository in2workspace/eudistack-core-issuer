package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.Oid4VciCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.AuthServerNonceRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oid4vci/v1/deferred-credential-metadata")
@RequiredArgsConstructor
public class DeferredCredentialMetadataController {

    private final Oid4VciCredentialWorkflow oid4VciCredentialWorkflow;

    @PostMapping("/nonce")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<Void> bindAccessTokenByPreAuthorizedCode(@RequestBody AuthServerNonceRequest authServerNonceRequest) {
        String processId = UUID.randomUUID().toString();
        return oid4VciCredentialWorkflow.bindAccessTokenByPreAuthorizedCode(processId, authServerNonceRequest);
    }

}
