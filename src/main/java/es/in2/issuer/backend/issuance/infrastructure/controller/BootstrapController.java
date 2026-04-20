package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.issuance.domain.model.dto.BootstrapRequest;
import es.in2.issuer.backend.issuance.domain.service.BootstrapTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
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
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.BOOTSTRAP_PATH;

@Slf4j
@RestController
@RequiredArgsConstructor
public class BootstrapController {

    private static final String BOOTSTRAP_TOKEN_HEADER = "X-Bootstrap-Token";
    // Kept in sync with TenantDomainWebFilter.TENANT_NAME_PATTERN — bootstrap is
    // cross-tenant and performs its own validation because the filter bypasses
    // this path.
    private static final Pattern TENANT_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

    private final BootstrapTokenService bootstrapTokenService;
    private final IssuanceWorkflow issuanceWorkflow;
    private final AuditService auditService;
    private final TenantRegistryService tenantRegistryService;

    @PostMapping(BOOTSTRAP_PATH)
    public Mono<ResponseEntity<Void>> bootstrapIssueCredential(
            @RequestHeader(BOOTSTRAP_TOKEN_HEADER) String bootstrapToken,
            @Valid @RequestBody BootstrapRequest request) {

        if (!bootstrapTokenService.consumeIfValid(bootstrapToken)) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "Invalid or already consumed bootstrap token"));
        }

        String tenant = request.tenant() == null ? null : request.tenant().trim();
        if (tenant == null || tenant.isBlank()) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "INVALID_TENANT: tenant is required"));
        }
        if (!TENANT_NAME_PATTERN.matcher(tenant).matches()) {
            log.warn("Rejected malformed tenant identifier '{}' on bootstrap", tenant);
            return Mono.error(new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "INVALID_TENANT: '" + tenant + "' is not a valid schema name"));
        }

        return tenantRegistryService.getActiveTenantSchemas()
                .flatMap(schemas -> {
                    if (!schemas.contains(tenant)) {
                        log.warn("Tenant '{}' not found in tenant_registry on bootstrap", tenant);
                        return Mono.<ResponseEntity<Void>>error(new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "TENANT_NOT_FOUND: Tenant '" + tenant + "' does not exist"));
                    }
                    String processId = UUID.randomUUID().toString();
                    auditService.auditSuccess("bootstrap.token.used", null, "bootstrap", processId,
                            Map.of("tenant", tenant));
                    log.info("[{}] Bootstrap issuance initiated for tenant '{}'", processId, tenant);

                    return issuanceWorkflow
                            .issueCredentialWithoutAuthorization(processId, request.toIssuanceRequest())
                            .<ResponseEntity<Void>>map(response -> {
                                if (response.credentialOfferUri() != null) {
                                    return ResponseEntity.created(URI.create(response.credentialOfferUri())).build();
                                }
                                return ResponseEntity.accepted().build();
                            })
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
                });
    }
}
