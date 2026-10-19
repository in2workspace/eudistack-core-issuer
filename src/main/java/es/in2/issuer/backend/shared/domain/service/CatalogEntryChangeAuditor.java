package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryChange;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.SYSTEM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Records, for every committed change to an entry of the attestation catalog, one
 * {@code tenant.credential_catalog.entry.changed} audit event (EUD-266, AC-12): who changed it, which entry,
 * what was done and what changed field by field.
 *
 * <p>"Who" is the person behind the request, the principal of the reactive security context (as
 * {@code RevocationWorkflow} resolves its actor), and not the administrator organization, which goes in the
 * details as {@code organization_id}. Both are read from the security context of the request, so the callers
 * only hand over the changes and call this once the transaction has committed.
 *
 * <p>Best-effort: the change is already committed and cannot be undone, so a failure to resolve the
 * identity or to write the event is logged and never fails the request.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CatalogEntryChangeAuditor {

    static final String EVENT = "tenant.credential_catalog.entry.changed";
    static final String RESOURCE_TYPE = "attestation-catalog";
    static final String UNKNOWN = "unknown";

    private final AuditService auditService;
    private final AccessTokenService accessTokenService;

    public Mono<Void> audit(CatalogEntryChange change) {
        return auditAll(List.of(change));
    }

    /** One event per change; the person and the organization are resolved once for all of them. */
    public Mono<Void> auditAll(List<CatalogEntryChange> changes) {
        if (changes.isEmpty()) {
            return Mono.empty();
        }
        return Mono.deferContextual(ctx -> {
                    String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
                    return Mono.zip(resolveActor(), resolveOrganization())
                            .doOnNext(who -> changes.forEach(change ->
                                    auditService.auditSuccess(EVENT, who.getT1(), RESOURCE_TYPE, tenant,
                                            details(change, who.getT2()))))
                            .then();
                })
                .onErrorResume(e -> {
                    log.warn("Catalog audit: could not record {} change(s), error={}", changes.size(), e.toString());
                    return Mono.empty();
                });
    }

    private static Map<String, Object> details(CatalogEntryChange change, String organizationId) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("action", change.action().value());
        details.put("credential_configuration_id", change.credentialConfigurationId());
        details.put("organization_id", organizationId);
        details.put("changes", change.changes());
        details.put("version", change.version());
        return details;
    }

    private Mono<String> resolveActor() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth != null && auth.isAuthenticated() && auth.getName() != null)
                .map(Authentication::getName)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("Catalog audit: the person is not resolvable from the security context");
                    return Mono.just(UNKNOWN);
                }));
    }

    private Mono<String> resolveOrganization() {
        return accessTokenService.getOrganizationIdFromCurrentSession()
                .onErrorResume(e -> {
                    log.warn("Catalog audit: the organization is not resolvable from the access token");
                    return Mono.empty();
                })
                .defaultIfEmpty(UNKNOWN);
    }
}
