package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.issuance.domain.model.dto.BootstrapRequest;
import es.in2.issuer.backend.issuance.domain.service.BootstrapTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.BOOTSTRAP_PATH;

@Slf4j
@RestController
@RequiredArgsConstructor
public class BootstrapController {

    private static final String BOOTSTRAP_TOKEN_HEADER = "X-Bootstrap-Token";

    private final BootstrapTokenService bootstrapTokenService;
    private final IssuanceWorkflow issuanceWorkflow;
    private final AuditService auditService;
    private final UrlResolver urlResolver;

    @PostMapping(BOOTSTRAP_PATH)
    public Mono<ResponseEntity<Void>> bootstrapIssueCredential(
            @RequestHeader(BOOTSTRAP_TOKEN_HEADER) String bootstrapToken,
            @Valid @RequestBody BootstrapRequest request,
            ServerWebExchange exchange) {

        if (!bootstrapTokenService.consumeIfValid(bootstrapToken)) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "Invalid or already consumed bootstrap token"));
        }

        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);

        // Tenant resolution and registry validation are performed by
        // TenantDomainWebFilter from the X-Tenant-Id header (or hostname).
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            if (tenant == null || tenant.isBlank()) {
                return Mono.error(new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "INVALID_TENANT: X-Tenant-Id header is required"));
            }

            String processId = UUID.randomUUID().toString();
            auditService.auditSuccess("bootstrap.token.used", null, "bootstrap", processId,
                    Map.of("tenant", tenant));
            log.info("[{}] Bootstrap issuance initiated for tenant '{}'", processId, tenant);

            return issuanceWorkflow
                    .issueCredentialWithoutAuthorization(processId, request.toIssuanceRequest(), bootstrapToken, publicIssuerBaseUrl)
                    .<ResponseEntity<Void>>map(response -> {
                        if (response.credentialOfferUri() != null) {
                            return ResponseEntity.created(URI.create(response.credentialOfferUri())).build();
                        }
                        return ResponseEntity.accepted().build();
                    });
        });
    }
}
