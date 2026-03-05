package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.UUID;

@Slf4j
@RestController
@RequiredArgsConstructor
public class IssuanceController {

    private final IssuanceWorkflow issuanceWorkflow;
    private final AccessTokenService accessTokenService;

    @PostMapping(
            value = "/v1/issuances",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<Void>> issueCredential(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken,
            @RequestHeader(name = "X-Id-Token", required = false) String idToken,
            @RequestBody PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest) {
        String processId = UUID.randomUUID().toString();
        return accessTokenService.getCleanBearerToken(bearerToken)
                .flatMap(token -> issuanceWorkflow.execute(processId, preSubmittedCredentialDataRequest, token, idToken))
                .map(this::toResponseEntity);
    }

    private ResponseEntity<Void> toResponseEntity(IssuanceResponse response) {
        if (response.credentialOfferUri() != null) {
            return ResponseEntity.created(URI.create(response.credentialOfferUri())).build();
        }
        return ResponseEntity.accepted().build();
    }

}
