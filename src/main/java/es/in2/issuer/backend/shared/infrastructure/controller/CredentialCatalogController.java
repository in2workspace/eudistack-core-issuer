package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.UpdateCredentialCatalogRequest;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.policy.service.CatalogPdpService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.Constants.SYSTEM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ATTESTATION_CATALOG_PATH;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_CATALOG_PATH;

/**
 * <b>Deprecated</b> backoffice API for the per-tenant credential catalog (EUD-72, US-02, EUD-169), kept
 * for the portal while it moves to the Attestation Catalogue API ({@link AttestationCatalogController}).
 * Every response carries {@code Deprecation} and a {@code Link} to its successor (RFC 9745). The PUT no
 * longer deletes the types it leaves out: it disables them (EUD-266, D5), so their configuration is kept.
 * Errors are {@code application/problem+json}, see {@link CatalogExceptionHandler}.
 *
 * <p>The tenant is always resolved from the reactive context (subdomain / X-Tenant), never from the
 * request body — see {@code TenantDomainWebFilter}. Not an admin-only path (see AD-16): the read side
 * is also reachable by the tenant's operator role, see the authorization breakdown below.
 *
 * <p>Reads and writes are authorized separately, and since the operator-read delta (AD-16)
 * they no longer share a gate:
 * <ul>
 *     <li><b>GET</b> is authorized by {@link CatalogPdpService#authorizeRead} — a tenant administrator,
 *         SysAdmin (including the cross-tenant read-only view from {@code platform}), or
 *         the tenant's operator ({@code LEAR}), who needs to discover a type's eligible
 *         delivery modes and schema ceiling before attempting to issue it.</li>
 *     <li><b>PUT</b> is authorized by {@link CatalogPdpService#authorizeWrite} (tenant
 *         administrator with write access, EUD-266) — never delegating to the read gate, so
 *         relaxing the read side can never relax the write side as a side effect.</li>
 * </ul>
 *
 * <p>The PUT receives its body as a {@code Mono}, subscribed only once the PDP has allowed the caller, so an
 * operator who sends a malformed body gets {@code insufficient_permission}, not 400.
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
    /**
     * RFC 9745 {@code Deprecation} value: the moment the alias was deprecated, 2026-10-19T00:00:00Z (the day
     * the Attestation Catalogue API replaced it), as a Structured Field Date ({@code @} and epoch seconds).
     */
    private static final String DEPRECATED_SINCE = "@" + Instant.parse("2026-10-19T00:00:00Z").getEpochSecond();

    private final CatalogPdpService catalogPdpService;
    private final TenantCredentialProfileService tenantCredentialProfileService;
    private final AuditService auditService;

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public Mono<List<CredentialCatalogEntryDto>> getCatalog(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            ServerHttpRequest request,
            ServerHttpResponse response) {
        markDeprecated(request, response);
        return catalogPdpService.authorizeRead(authorizationHeader)
                .then(Mono.defer(tenantCredentialProfileService::getCatalog));
    }

    @PutMapping
    @ResponseStatus(HttpStatus.OK)
    public Mono<Void> updateCatalog(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @Valid @RequestBody Mono<UpdateCredentialCatalogRequest> body,
            ServerHttpRequest httpRequest,
            ServerHttpResponse response) {
        markDeprecated(httpRequest, response);
        return catalogPdpService.authorizeWrite(authorizationHeader)
                .flatMap(ctx -> body.flatMap(request -> Mono.deferContextual(reactorCtx -> {
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
                })));
    }

    /**
     * RFC 9745: {@code Deprecation} says since when, {@code Link rel="successor-version"} where to go. The
     * link is relative to the host root with the context path, like {@code Location} of the new API (D11).
     * Set up front, so it is also on the error responses.
     */
    private static void markDeprecated(ServerHttpRequest request, ServerHttpResponse response) {
        response.getHeaders().set("Deprecation", DEPRECATED_SINCE);
        response.getHeaders().add(HttpHeaders.LINK, "<" + request.getPath().contextPath().value()
                + ATTESTATION_CATALOG_PATH + ">; rel=\"successor-version\"");
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
}
