package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.AuditTrailUnavailableException;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Holder;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceDetail;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceSummary;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.model.query.PageCursor;
import es.in2.issuer.backend.shared.domain.model.query.PagePosition;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.IssuanceQueryService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.PLATFORM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Listing and detail of the issuance processes (EUD-255 design 1.1, AD-1 and AD-3). The tenant isolation comes
 * from the search_path of the tenant in the context; the organization scope from the decision.
 *
 * <p>Each page asks one row more than its size: if it comes, there is a next page and its cursor is
 * the position of the last process returned.
 */
@Service
@RequiredArgsConstructor
public class IssuanceQueryServiceImpl implements IssuanceQueryService {

    static final String CURSOR = "cursor";
    static final String TENANT = "tenant";

    private final IssuancePort issuancePort;
    private final TenantRegistryService tenantRegistryService;
    private final PowerAuthorizationService powerAuthorizationService;
    private final AuditTrailPort auditTrail;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<IssuanceList> list(AuthorizationDecision decision, IssuanceQuery query) {
        return Mono.defer(() -> {
            if (query.cursor() != null && !query.cursor().filterDigest().equals(query.filterDigest())) {
                return Mono.error(InvalidQueryException.of(CURSOR, "was given for other filters"));
            }
            boolean crossTenant = decision.caller().crossTenantView();
            if (query.tenant() != null && !crossTenant) {
                return Mono.error(InvalidQueryException.of(TENANT, "is only accepted from the platform tenant"));
            }
            int fetchSize = query.limit() + 1;
            Mono<List<Found>> found = crossTenant
                    ? acrossTenants(query, fetchSize)
                    : issuancePort.findPage(query, organizationScope(decision), fetchSize)
                            .map(issuance -> new Found(null, issuance))
                            .collectList();
            return found.map(rows -> toPage(rows, query))
                    .flatMap(page -> stageStrictly(IssuanceAuditEvents.queried(
                                    decision.caller().organizationIdentifier(), query.filters(), page.issuances().size()))
                            .thenReturn(page));
        });
    }

    /**
     * The permission is decided with the organization stored with the process in the tenant: one of another
     * organization reads as not found. An id that is not in the tenant is decided without a resource -- the
     * platform administrator's cross-tenant view finds it in another schema, everyone else gets not found.
     * Every refusal with a reason in the catalogue is traced before it is answered.
     */
    @Override
    public Mono<IssuanceDetail> detail(UUID issuanceId) {
        String id = issuanceId.toString();
        Mono<IssuanceDetail> detail = issuancePort.findByIssuanceId(issuanceId)
                .map(stored -> Optional.of(Objects.requireNonNullElse(stored.getOrganizationIdentifier(), "")))
                .defaultIfEmpty(Optional.empty())
                .flatMap(organization -> powerAuthorizationService.authorizeQuery(organization.orElse(null), id))
                .flatMap(decision -> find(decision, issuanceId))
                .switchIfEmpty(Mono.error(() -> new IssuanceNotFoundException("No issuance found for the given id")))
                .flatMap(process -> toDetail(process)
                        .flatMap(result -> stageDetailAccessed(process).thenReturn(result)));
        return detail.onErrorResume(error -> detailRefusalOf(error)
                .map(reason -> stageStrictly(IssuanceAuditEvents.detailRefused(id, reason)).then(Mono.<IssuanceDetail>error(error)))
                .orElseGet(() -> Mono.error(error)));
    }

    /** The reason of the catalogue for a refused detail; empty for an error that is not a refusal. */
    private static Optional<String> detailRefusalOf(Throwable error) {
        if (error instanceof IssuanceNotFoundException) {
            return Optional.of(IssuanceAuditEvents.REASON_ISSUANCE_NOT_FOUND);
        }
        if (error instanceof LearIssuancePolicyException || error instanceof TenantMismatchException) {
            return Optional.of(IssuanceAuditEvents.REASON_POLICY_DENIED);
        }
        return Optional.empty();
    }

    /**
     * AD-7: the trace of a read is staged in a transaction of its own and, if it cannot be, the read fails
     * and returns nothing. Replaces the best effort of EUD-244 for the queries.
     */
    private Mono<Void> stageStrictly(AuditEntry entry) {
        return auditTrail.stageInNewTransaction(entry).onErrorMap(AuditTrailUnavailableException::new);
    }

    /**
     * The tenant isolation comes from the search_path; the scope from the decision. From the platform tenant
     * the process is looked up in the schema of every active tenant, and the one it is in is returned with it.
     */
    private Mono<Found> find(AuthorizationDecision decision, UUID issuanceId) {
        return Mono.defer(() -> {
            Mono<Found> found;
            if (decision.caller().crossTenantView()) {
                found = tenantRegistryService.getActiveTenantSchemas()
                        .flatMapMany(Flux::fromIterable)
                        .filter(tenant -> !PLATFORM_TENANT.equals(tenant))
                        .concatMap(tenant -> issuancePort.findByIssuanceId(issuanceId)
                                .map(issuance -> new Found(tenant, issuance))
                                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant)))
                        .next();
            } else if (decision.anyOrganization()) {
                found = issuancePort.findByIssuanceId(issuanceId).map(issuance -> new Found(null, issuance));
            } else {
                found = issuancePort.findByIssuanceIdAndOrganizationIdentifier(
                                issuanceId, decision.caller().organizationIdentifier())
                        .map(issuance -> new Found(null, issuance));
            }
            return found;
        });
    }

    /**
     * EUD-244: the access is staged once, strictly (AD-7). When a platform administrator read a process of
     * another tenant, it is staged under that tenant, which owns the data and the holder in it, and the
     * administrator stays as the actor (D62).
     */
    private Mono<Void> stageDetailAccessed(Found found) {
        Issuance issuance = found.issuance();
        Mono<Void> access = stageStrictly(IssuanceAuditEvents.detailAccessed(
                issuance.getIssuanceId().toString(),
                Holder.ofAttestation(issuance.getSubject(), issuance.getEmail(), issuance.getCredentialDataSet())));
        return found.tenant() == null ? access : auditTrail.inTenant(found.tenant(), access);
    }

    private Mono<IssuanceDetail> toDetail(Found found) {
        String credentialDataSet = found.issuance().getCredentialDataSet();
        if (credentialDataSet == null) {
            return Mono.error(new ParseCredentialJsonException("The issuance process has no attestation data"));
        }
        try {
            return Mono.just(new IssuanceDetail(toSummary(found), objectMapper.readTree(credentialDataSet)));
        } catch (JsonProcessingException e) {
            return Mono.error(new ParseCredentialJsonException("The attestation data of the issuance process is not JSON"));
        }
    }

    /** Null for a caller who sees the whole tenant, its organization otherwise. */
    private static String organizationScope(AuthorizationDecision decision) {
        return decision.anyOrganization() ? null : decision.caller().organizationIdentifier();
    }

    /**
     * AD-3: the same page in the schema of each active tenant -- or only the one asked for -- merged
     * by position. The order is the same in every schema and an issuance id is unique across them,
     * so the merge is exact and the cursor serves every schema. A tenant that fails fails the page:
     * an incomplete page is never returned as complete. The platform tenant has no processes.
     */
    private Mono<List<Found>> acrossTenants(IssuanceQuery query, int fetchSize) {
        return tenantRegistryService.getActiveTenantSchemas()
                .flatMap(active -> {
                    List<String> tenants = active.stream().filter(tenant -> !PLATFORM_TENANT.equals(tenant)).toList();
                    if (query.tenant() == null) {
                        return Mono.just(tenants);
                    }
                    return tenants.contains(query.tenant())
                            ? Mono.just(List.of(query.tenant()))
                            : Mono.error(InvalidQueryException.of(TENANT, "is not an active tenant"));
                })
                .flatMapMany(Flux::fromIterable)
                .flatMap(tenant -> issuancePort.findPage(query, null, fetchSize)
                        .map(issuance -> new Found(tenant, issuance))
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant)))
                .collectSortedList(Comparator.comparing(Found::position, PagePosition.NEWEST_FIRST))
                .map(rows -> rows.size() > fetchSize ? rows.subList(0, fetchSize) : rows);
    }

    private static IssuanceList toPage(List<Found> rows, IssuanceQuery query) {
        boolean more = rows.size() > query.limit();
        List<Found> page = more ? rows.subList(0, query.limit()) : rows;
        String nextCursor = more
                ? new PageCursor(page.getLast().position(), query.filterDigest()).encode()
                : null;
        return new IssuanceList(page.stream().map(IssuanceQueryServiceImpl::toSummary).toList(), nextCursor);
    }

    private static IssuanceSummary toSummary(Found found) {
        Issuance issuance = found.issuance();
        return IssuanceSummary.builder()
                .id(issuance.getIssuanceId())
                .organizationIdentifier(issuance.getOrganizationIdentifier())
                .credentialConfigurationId(issuance.getCredentialType())
                .credentialFormat(issuance.getCredentialFormat())
                .lifeCycleStatus(issuance.getCredentialStatus() == null ? null : issuance.getCredentialStatus().name())
                .subject(issuance.getSubject())
                .email(issuance.getEmail())
                .delivery(issuance.getDelivery())
                .validFrom(toInstant(issuance.getValidFrom()))
                .validUntil(toInstant(issuance.getValidUntil()))
                .created(issuance.getCreatedAt())
                .createdBy(issuance.getCreatedBy())
                .updated(issuance.getLastChangedAt())
                .tenant(found.tenant())
                .build();
    }

    private static Instant toInstant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    /** A process of a page and the tenant it was found in, only from the platform tenant. */
    private record Found(String tenant, Issuance issuance) {
        PagePosition position() {
            return PagePosition.of(issuance);
        }
    }
}
