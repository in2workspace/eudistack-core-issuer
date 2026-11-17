package es.in2.issuer.backend.issuance.domain.service.impl;

import es.in2.issuer.backend.issuance.domain.exception.UnknownOrganizationException;
import es.in2.issuer.backend.issuance.domain.service.TenantOrganizationService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * The organizations of a tenant, as far as the platform records them today.
 *
 * <p>A simple tenant has one organization, the one that governs it (platform model MP-01, MP-09): its
 * {@code admin_organization_id}. Any other organization is not of the tenant. A tenant whose type is not
 * recorded, or the platform tenant, is held to the same rule, so a missing registry row fails closed;
 * a tenant without {@code admin_organization_id} fails with the missing configuration.
 *
 * <p>A multi-organization tenant has no record of its organizations yet (TDG-25), so every organization
 * is accepted there, as before EUD-268: that case is tracked apart and is not decided here.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TenantOrganizationServiceImpl implements TenantOrganizationService {

    static final String MULTI_ORGANIZATION = "multi_org";
    static final String SIMPLE = "simple";
    static final String TENANT_ORGANIZATION_KEY = "admin_organization_id";
    /** The detail of the problem: fixed, it never names the organization sent nor the tenant. */
    static final String UNKNOWN_ORGANIZATION_DETAIL = "organization is not an organization of the tenant";

    private final TenantRegistryService tenantRegistryService;
    private final TenantConfigService tenantConfigService;

    @Override
    public Mono<Void> requireOrganizationOfTenant(String organizationIdentifier) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            return tenantRegistryService.getTenantType(tenant)
                    .defaultIfEmpty("")
                    .flatMap(type -> {
                        if (MULTI_ORGANIZATION.equals(type)) {
                            return Mono.<Void>empty();
                        }
                        if (!SIMPLE.equals(type)) {
                            log.warn("Tenant {} has type '{}': only its own organization is accepted in organization",
                                    tenant, type);
                        }
                        return tenantConfigService.getStringOrThrow(TENANT_ORGANIZATION_KEY)
                                .flatMap(ownOrganization -> ownOrganization.equals(organizationIdentifier)
                                        ? Mono.<Void>empty()
                                        : Mono.error(new UnknownOrganizationException(UNKNOWN_ORGANIZATION_DETAIL)));
                    });
        });
    }
}
