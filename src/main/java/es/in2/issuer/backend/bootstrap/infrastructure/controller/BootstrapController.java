package es.in2.issuer.backend.bootstrap.infrastructure.controller;

import es.in2.issuer.backend.bootstrap.domain.service.BootstrapTokenService;
import es.in2.issuer.backend.shared.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping
@RequiredArgsConstructor
public class BootstrapController {

    private static final String BOOTSTRAP_TOKEN_HEADER = "X-Bootstrap-Token";

    private final BootstrapTokenService bootstrapTokenService;
    private final IssuanceWorkflow issuanceWorkflow;

    @PostMapping("/bootstrap/v1/issuances")
    public Mono<ResponseEntity<Void>> bootstrapIssueCredential(
            @RequestHeader(BOOTSTRAP_TOKEN_HEADER) String bootstrapToken,
            @Valid @RequestBody PreSubmittedCredentialDataRequest request) {

        if (!bootstrapTokenService.consumeIfValid(bootstrapToken)) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "Invalid or already consumed bootstrap token"));
        }

        String processId = UUID.randomUUID().toString();
        log.info("[{}] Bootstrap issuance initiated", processId);

        return issuanceWorkflow.issueCredentialWithoutAuthorization(processId, request)
                .map(response -> {
                    if (response.credentialOfferUri() != null) {
                        return ResponseEntity.created(URI.create(response.credentialOfferUri())).<Void>build();
                    }
                    return ResponseEntity.<Void>accepted().build();
                });
    }
}
