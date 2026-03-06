package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequiredArgsConstructor
public class IssuanceController {

    private final IssuanceWorkflow issuanceWorkflow;

    @PostMapping(
            value = "/v1/issuances",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<IssuanceResponse>> issueCredential(
            @RequestHeader(name = "X-Id-Token", required = false) String idToken,
            @Valid @RequestBody PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest) {
        String processId = UUID.randomUUID().toString();
        return issuanceWorkflow.issueCredential(processId, preSubmittedCredentialDataRequest, idToken)
                .map(this::toResponseEntity);
    }

    private ResponseEntity<IssuanceResponse> toResponseEntity(IssuanceResponse response) {
        if (response.credentialOfferUri() != null) {
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

}
