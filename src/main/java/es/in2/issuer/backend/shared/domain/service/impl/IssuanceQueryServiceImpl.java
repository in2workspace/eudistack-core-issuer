package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.AuditTrailUnavailableException;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceQueryUnavailableException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.UnknownIdentifierTypeException;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprinter;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
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
 * Listing, search and detail of the issuance processes (EUD-255 design 1.1, AD-1, AD-3, AD-4 and AD-9). The tenant
 * isolation comes from the search_path of the tenant in the context; the organization scope from the decision.
 *
 * <p>Each page asks one row more than its size: if it comes, there is a next page and its cursor is
 * the position of the last process returned.
 */
@Service
@RequiredArgsConstructor
public class IssuanceQueryServiceImpl implements IssuanceQueryService {

    static final String CURSOR = "cursor";
    static final String TENANT = "tenant";
    /** The fingerprint of a value that normalizes to nothing: no process has it. */
    private static final byte[] NO_FINGERPRINT = new byte[0];

    private final IssuancePort issuancePort;
    private final TenantRegistryService tenantRegistryService;
    private final PowerAuthorizationService powerAuthorizationService;
    private final AuditTrailPort auditTrail;
    private final ObjectMapper objectMapper;
    private final CatalogEntryPort catalogEntryPort;
    private final TenantSecretKeyPort tenantSecretKeyPort;

    @Override
    public Mono<IssuanceList> list(AuthorizationDecision decision, IssuanceQuery query) {
        return Mono.defer(() -> {
            boolean crossTenant = decision.caller().crossTenantView();
            if (query.tenant() != null && !crossTenant) {
                return Mono.error(InvalidQueryException.of(TENANT, "is only accepted from the platform tenant"));
            }
            if (query.identifier() == null) {
                return page(decision, query, query, crossTenant);
            }
            if (crossTenant && query.tenant() == null) {
                return Mono.error(InvalidQueryException.of(TENANT, "is required to search by identifier"));
            }
            return fingerprinted(decision, query, crossTenant)
                    .flatMap(searched -> page(decision, query, searched, crossTenant));
        });
    }

    /**
     * A page of {@code searched}, traced with the filters of {@code received}: the same query, but for a search by
     * identifier, whose value only the trace keeps while the page is searched by its fingerprint.
     */
    private Mono<IssuanceList> page(AuthorizationDecision decision, IssuanceQuery received, IssuanceQuery searched,
                                    boolean crossTenant) {
        if (searched.cursor() != null && !searched.cursor().filterDigest().equals(searched.filterDigest())) {
            return Mono.error(InvalidQueryException.of(CURSOR, "was given for other filters"));
        }
        int fetchSize = searched.limit() + 1;
        Mono<List<Found>> found = crossTenant
                ? acrossTenants(searched, fetchSize)
                : stored(issuancePort.findPage(searched, organizationScope(decision), fetchSize))
                        .map(issuance -> new Found(null, issuance))
                        .collectList();
        return found.map(rows -> toPage(rows, searched))
                .flatMap(page -> stageStrictly(IssuanceAuditEvents.queried(
                                decision.caller().organizationIdentifier(), received.filters(), page.issuances().size()))
                        .thenReturn(page));
    }

    /**
     * EUD-255 FR-05, AD-4 and AD-5: the search by identifier of the query turned into its fingerprint, computed with
     * the single component of the issuance and the key of the tenant searched -- the caller's, or from the platform
     * tenant the one it names, which must be active. A type that no catalogue entry of that tenant declares is
     * refused as {@code unknown_identifier_type}, traced first. A catalogue or a key that cannot be read fails as
     * {@code internal_error}; the other queries do not need either.
     */
    private Mono<IssuanceQuery> fingerprinted(AuthorizationDecision decision, IssuanceQuery query, boolean crossTenant) {
        String type = query.identifier().type();
        Mono<String> tenant = crossTenant ? activeTenant(query.tenant()) : currentTenant();
        return tenant.flatMap(name -> declares(type)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, name))
                .flatMap(declared -> Boolean.TRUE.equals(declared)
                        ? tenantSecretKeyPort.keyOf(name)
                                .onErrorMap(IssuanceQueryUnavailableException::new)
                                .map(key -> query.withIdentifierFingerprint(SearchIdentifierFingerprinter
                                        .fingerprint(key, query.identifier().value())
                                        .orElse(NO_FINGERPRINT)))
                        : stageStrictly(IssuanceAuditEvents.queryRefused(decision.caller().organizationIdentifier(),
                                        query.filters(), IssuanceAuditEvents.REASON_UNKNOWN_IDENTIFIER_TYPE))
                                .then(Mono.<IssuanceQuery>error(UnknownIdentifierTypeException::new))));
    }

    /** Whether an entry of the catalogue of the tenant in the context declares a search identifier of that name. */
    private Mono<Boolean> declares(String type) {
        return stored(catalogEntryPort.findAll())
                .any(entry -> entry.searchIdentifiers().stream().anyMatch(identifier -> identifier.name().equals(type)));
    }

    private static Mono<String> currentTenant() {
        return Mono.deferContextual(ctx -> ctx.<String>getOrEmpty(TENANT_DOMAIN_CONTEXT_KEY)
                .map(Mono::just)
                .orElseGet(() -> Mono.error(new IssuanceQueryUnavailableException(
                        new IllegalStateException("No tenant in the context")))));
    }

    /** The tenant named from the platform tenant, if it is an active one (the platform tenant has no processes). */
    private Mono<String> activeTenant(String tenant) {
        return activeTenants().flatMap(tenants -> tenants.contains(tenant)
                ? Mono.just(tenant)
                : Mono.error(InvalidQueryException.of(TENANT, "is not an active tenant")));
    }

    private Mono<List<String>> activeTenants() {
        return stored(tenantRegistryService.getActiveTenantSchemas())
                .map(active -> active.stream().filter(tenant -> !PLATFORM_TENANT.equals(tenant)).toList());
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
        Mono<IssuanceDetail> detail = stored(issuancePort.findByIssuanceId(issuanceId))
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
     * AD-3: a read of the processes that fails -- a schema of one tenant, the registry of tenants -- fails the
     * whole request as {@code internal_error}; nothing partial is returned as complete.
     */
    private static <T> Flux<T> stored(Flux<T> rows) {
        return rows.onErrorMap(IssuanceQueryUnavailableException::new);
    }

    private static <T> Mono<T> stored(Mono<T> row) {
        return row.onErrorMap(IssuanceQueryUnavailableException::new);
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
                found = stored(tenantRegistryService.getActiveTenantSchemas())
                        .flatMapMany(Flux::fromIterable)
                        .filter(tenant -> !PLATFORM_TENANT.equals(tenant))
                        .concatMap(tenant -> stored(issuancePort.findByIssuanceId(issuanceId))
                                .map(issuance -> new Found(tenant, issuance))
                                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant)))
                        .next();
            } else if (decision.anyOrganization()) {
                found = stored(issuancePort.findByIssuanceId(issuanceId)).map(issuance -> new Found(null, issuance));
            } else {
                found = stored(issuancePort.findByIssuanceIdAndOrganizationIdentifier(
                                issuanceId, decision.caller().organizationIdentifier()))
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
        } catch (JsonProcessingException _) {
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
        Mono<List<String>> tenants = query.tenant() == null
                ? activeTenants()
                : activeTenant(query.tenant()).map(List::of);
        return tenants
                .flatMapMany(Flux::fromIterable)
                .flatMap(tenant -> stored(issuancePort.findPage(query, null, fetchSize))
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
