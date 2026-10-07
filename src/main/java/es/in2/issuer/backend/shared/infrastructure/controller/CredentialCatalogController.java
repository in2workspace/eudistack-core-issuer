package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.UpdateCredentialCatalogRequest;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.Constants.SYSTEM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_CATALOG_PATH;

/**
 * Backoffice API for the per-tenant credential catalog (EUD-72, US-02, EUD-169). The tenant is
 * always resolved from the reactive context (subdomain / X-Tenant), never from the request
 * body — see {@code TenantDomainWebFilter}. Not an admin-only path (see AD-16): the read side
 * is also reachable by the tenant's operator role, see the authorization breakdown below.
 *
 * <p>Reads and writes are authorized separately, and since the operator-read delta (AD-16)
 * they no longer share a gate:
 * <ul>
 *     <li><b>GET</b> requires {@code canReadCredentialCatalog()} — a tenant administrator,
 *         SysAdmin (including the cross-tenant read-only view from {@code platform}), or
 *         the tenant's operator ({@code LEAR}), who needs to discover a type's eligible
 *         delivery modes and schema ceiling before attempting to issue it.</li>
 *     <li><b>PUT</b> independently requires {@code isTenantAdmin()} <b>and</b>
 *         {@code canWrite()} — checked without delegating to the read gate, so relaxing the
 *         read side can never relax the write side as a side effect.</li>
 * </ul>
 *
 *
 * <p>An empty catalog is not a valid state: <b>PUT</b> with an empty
 * {@code enabledConfigurationIds} is rejected (400, bean validation) and <b>GET</b> answers
 * 404 when the tenant has no enabled configuration at all.
 */
@RestController
@RequestMapping(CREDENTIAL_CATALOG_PATH)
@RequiredArgsConstructor
public class CredentialCatalogController {

    private static final String AUDIT_EVENT = "tenant.credential_catalog.changed";
    private static final String AUDIT_RESOURCE_TYPE = "credential-catalog";
    private static final String ACTION_REPLACE_CATALOG = "replace_catalog";
    private static final String AUDIT_EVENT_TENANT_BREACH = "tenant_isolation_breach";
    private static final String AUDIT_EVENT_AUTHZ_DENY = "authorization.deny";

    private final AccessTokenService accessTokenService;
    private final TenantCredentialProfileService tenantCredentialProfileService;
    private final AuditService auditService;

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<List<CredentialCatalogEntryDto>> getCatalog(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return authorizeCatalogRead(authorizationHeader)
                .then(Mono.defer(tenantCredentialProfileService::getCatalog));
    }

    @PutMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<Void> updateCatalog(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @Valid @RequestBody UpdateCredentialCatalogRequest request) {
        return authorizeTenantAdminWrite(authorizationHeader)
                .flatMap(ctx -> Mono.deferContextual(reactorCtx -> {
                    String tenant = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
                    return tenantCredentialProfileService.updateCatalog(
                                    request.enabledConfigurationIds(),
                                    parseDeliveryModes(request.deliveryModesByConfigurationId()))
                            .doOnSuccess(v -> auditService.auditSuccess(AUDIT_EVENT, ctx.organizationIdentifier(),
                                    AUDIT_RESOURCE_TYPE, tenant, Map.of(
                                            "action", ACTION_REPLACE_CATALOG,
                                            "enabledConfigurationIds", request.enabledConfigurationIds(),
                                            "deliveryModesByConfigurationId",
                                            request.deliveryModesByConfigurationId() == null ? Map.of() : request.deliveryModesByConfigurationId(),
                                            "sysAdmin", ctx.isSysAdmin())))
                            .doOnError(e -> auditService.auditFailure(AUDIT_EVENT, ctx.organizationIdentifier(),
                                    e.getClass().getSimpleName(), Map.of("tenant", tenant)));
                }));
    }

    private Map<String, Set<DeliveryMode>> parseDeliveryModes(Map<String, Set<String>> deliveryModesByConfigurationId) {
        if (deliveryModesByConfigurationId == null) {
            return Map.of();
        }
        return deliveryModesByConfigurationId.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> parseModes(entry.getKey(), entry.getValue())));
    }

    private Set<DeliveryMode> parseModes(String credentialConfigurationId, Set<String> rawModes) {
        // Defense in depth alongside UpdateCredentialCatalogRequest's @NotNull/@Size container-element
        // constraints (F3, security review): a JSON-null value for a declared key must not reach
        // String.join as an NPE -- it is the same class of input error as an empty set (ES-02).
        if (rawModes == null || rawModes.isEmpty()) {
            throw new InvalidDeliveryConfigException(
                    "No delivery modes declared for credential configuration id '" + credentialConfigurationId + "'");
        }
        try {
            return DeliveryMode.parse(String.join(",", rawModes));
        } catch (IllegalArgumentException e) {
            throw new InvalidDeliveryConfigException(
                    "Invalid delivery modes for credential configuration id '" + credentialConfigurationId + "': " + e.getMessage());
        }
    }

    private Mono<AuthorizationContext> authorizeCatalogRead(String authorizationHeader) {
        return accessTokenService.getAuthorizationContext(authorizationHeader)
                .flatMap(ctx -> {
                    if (!ctx.canReadCredentialCatalog()) {
                        // Unreachable today -- UserRole has exactly three values and all three
                        // pass canReadCredentialCatalog() (see its javadoc / the exhaustiveness
                        // tripwire test). Kept audited so a future fourth role's denial is not
                        // silently invisible the day this stops being vacuous.
                        return auditDenyThenForbid(ctx, "read_catalog",
                                "Tenant administrator, SysAdmin or operator role required");
                    }
                    return requireTenantMatch(ctx, authorizationHeader);
                });
    }

    /**
     * Deliberately does not delegate to {@link #authorizeCatalogRead}: since AD-16 opened
     * the read gate to the operator ({@code LEAR}), and a {@code LEAR} has
     * {@code readOnly == false}, delegating would silently open the write path to the
     * operator too. Checked independently, in one place, so relaxing the read side can
     * never relax this one as a side effect.
     */
    private Mono<AuthorizationContext> authorizeTenantAdminWrite(String authorizationHeader) {
        return accessTokenService.getAuthorizationContext(authorizationHeader)
                .flatMap(ctx -> {
                    if (!ctx.isTenantAdmin() || !ctx.canWrite()) {
                        return auditDenyThenForbid(ctx, "write_catalog",
                                "Tenant administrator role with write access required");
                    }
                    return requireTenantMatch(ctx, authorizationHeader);
                });
    }


    private Mono<AuthorizationContext> requireTenantMatch(AuthorizationContext ctx, String authorizationHeader) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
            return accessTokenService.getTokenTenant(authorizationHeader)
                    .defaultIfEmpty("")
                    .flatMap(tokenTenant -> {
                        if (tokenTenant.isBlank() || !tokenTenant.equalsIgnoreCase(tenantDomain)) {
                            auditService.auditFailure(AUDIT_EVENT_TENANT_BREACH, ctx.organizationIdentifier(),
                                    "token_tenant_mismatch",
                                    Map.of("tokenTenant", tokenTenant, "resolvedTenant", tenantDomain));
                            return Mono.error(new TenantMismatchException(
                                    "Token tenant '" + tokenTenant + "' does not match tenant header '" + tenantDomain + "'"));
                        }
                        return Mono.just(ctx);
                    });
        });
    }

    private Mono<AuthorizationContext> auditDenyThenForbid(AuthorizationContext ctx, String action, String message) {
        return Mono.deferContextual(reactorCtx -> {
            String tenant = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
            auditService.auditFailure(AUDIT_EVENT_AUTHZ_DENY, ctx.organizationIdentifier(), "role_not_permitted",
                    Map.of("tenant", tenant, "action", action));
            return Mono.<AuthorizationContext>error(new ResponseStatusException(HttpStatus.FORBIDDEN, message));
        });
    }
}
