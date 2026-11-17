package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceDetail;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceSummary;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.model.query.PageCursor;
import es.in2.issuer.backend.shared.domain.model.query.PagePosition;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.support.TestAuthorizationDecisions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static es.in2.issuer.backend.shared.domain.util.Constants.PLATFORM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** EUD-255 AD-1 and AD-3: scope, pages and the merge of the platform tenant's view; the detail (FR-06). */
class IssuanceQueryServiceImplTest {

    private static final Instant T = Instant.parse("2026-10-01T09:00:00Z");

    private IssuancePort issuancePort;
    private TenantRegistryService tenantRegistryService;
    private RecordingAuditTrail auditTrail;
    private IssuanceQueryServiceImpl service;

    @BeforeEach
    void setUp() {
        issuancePort = mock(IssuancePort.class);
        tenantRegistryService = mock(TenantRegistryService.class);
        auditTrail = new RecordingAuditTrail();
        service = new IssuanceQueryServiceImpl(issuancePort, tenantRegistryService, auditTrail, new ObjectMapper());
    }

    @Test
    void anOrganizationAdmin_onlyQueriesItsOrganization() {
        IssuanceQuery query = query(Set.of(), null, 50, null);
        when(issuancePort.findPage(query, "ORG-A", 51)).thenReturn(Flux.empty());

        StepVerifier.create(service.list(organizationAdmin("ORG-A"), query))
                .assertNext(page -> {
                    assertThat(page.issuances()).isEmpty();
                    assertThat(page.nextCursor()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void aTenantAdmin_queriesTheWholeTenant() {
        IssuanceQuery query = query(Set.of(), null, 50, null);
        when(issuancePort.findPage(query, null, 51)).thenReturn(Flux.empty());

        StepVerifier.create(service.list(tenantAdmin(), query)).expectNextCount(1).verifyComplete();

        verify(issuancePort).findPage(query, null, 51);
    }

    @Test
    void oneRowMoreThanTheLimit_meansANextPage_whoseCursorIsTheLastProcessReturned() {
        IssuanceQuery query = query(Set.of(CredentialStatusEnum.VALID), null, 2, null);
        Issuance first = issuance(T.plusSeconds(3));
        Issuance second = issuance(T.plusSeconds(2));
        Issuance extra = issuance(T.plusSeconds(1));
        when(issuancePort.findPage(query, "ORG-A", 3)).thenReturn(Flux.just(first, second, extra));

        IssuanceList page = service.list(organizationAdmin("ORG-A"), query).block();

        assertThat(page.issuances()).extracting(IssuanceSummary::id)
                .containsExactly(first.getIssuanceId(), second.getIssuanceId());
        PageCursor next = PageCursor.decode(page.nextCursor()).orElseThrow();
        assertThat(next.position()).isEqualTo(PagePosition.of(second));
        assertThat(next.filterDigest()).isEqualTo(query.filterDigest());
    }

    @Test
    void exactlyTheLimit_isTheLastPage() {
        IssuanceQuery query = query(Set.of(), null, 2, null);
        when(issuancePort.findPage(query, "ORG-A", 3))
                .thenReturn(Flux.just(issuance(T.plusSeconds(2)), issuance(T.plusSeconds(1))));

        IssuanceList page = service.list(organizationAdmin("ORG-A"), query).block();

        assertThat(page.issuances()).hasSize(2);
        assertThat(page.nextCursor()).isNull();
    }

    /** EUD-244: each page leaves one IssuanceQueried with the number of processes returned. */
    @Test
    void eachPage_isAudited_withTheNumberReturned() {
        IssuanceQuery query = query(Set.of(), null, 2, null);
        when(issuancePort.findPage(query, "ORG-A", 3))
                .thenReturn(Flux.just(issuance(T.plusSeconds(3)), issuance(T.plusSeconds(2)), issuance(T.plusSeconds(1))));

        service.list(organizationAdmin("ORG-A"), query).block();

        assertThat(auditTrail.all()).singleElement().satisfies(entry -> {
            assertThat(entry.type()).isEqualTo(AuditEventType.ISSUANCE_QUERIED);
            assertThat(entry.details()).containsEntry("returned_count", 2);
        });
    }

    @Test
    void aCursorOfOtherFilters_isAnInvalidQuery() {
        PageCursor ofOtherFilters = new PageCursor(new PagePosition(T, UUID.randomUUID()),
                query(Set.of(CredentialStatusEnum.REVOKED), null, 50, null).filterDigest());
        IssuanceQuery query = query(Set.of(CredentialStatusEnum.VALID), null, 50, ofOtherFilters);

        StepVerifier.create(service.list(organizationAdmin("ORG-A"), query))
                .expectErrorSatisfies(error -> assertThat(((InvalidQueryException) error).violations())
                        .extracting(InvalidQueryException.Violation::field).containsExactly("cursor"))
                .verify();
        verifyNoInteractions(issuancePort);
    }

    @Test
    void theTenantFilter_isOnlyAcceptedFromThePlatformTenant() {
        IssuanceQuery query = query(Set.of(), "sandbox", 50, null);

        StepVerifier.create(service.list(tenantAdmin(), query))
                .expectErrorSatisfies(error -> assertThat(((InvalidQueryException) error).violations())
                        .extracting(InvalidQueryException.Violation::field).containsExactly("tenant"))
                .verify();
        verifyNoInteractions(issuancePort);
    }

    @Test
    void thePageMapsTheContractFields() {
        IssuanceQuery query = query(Set.of(), null, 50, null);
        Issuance issuance = issuance(T);
        issuance.setOrganizationIdentifier("ORG-A");
        issuance.setCredentialType("doctor.sd.1");
        issuance.setCredentialFormat("dc+sd-jwt");
        issuance.setSubject("María García López");
        issuance.setEmail("maria@example.com");
        issuance.setDelivery("email");
        issuance.setValidFrom(Timestamp.from(T.minusSeconds(60)));
        issuance.setValidUntil(Timestamp.from(T.plusSeconds(3600)));
        issuance.setCreatedAt(T.minusSeconds(120));
        issuance.setCreatedBy("admin@example.com");
        issuance.setUpdatedAt(T.plusSeconds(999));
        when(issuancePort.findPage(query, "ORG-A", 51)).thenReturn(Flux.just(issuance));

        IssuanceSummary summary = service.list(organizationAdmin("ORG-A"), query).block().issuances().getFirst();

        assertThat(summary).isEqualTo(IssuanceSummary.builder()
                .id(issuance.getIssuanceId())
                .organizationIdentifier("ORG-A")
                .credentialConfigurationId("doctor.sd.1")
                .credentialFormat("dc+sd-jwt")
                .lifeCycleStatus("VALID")
                .subject("María García López")
                .email("maria@example.com")
                .delivery("email")
                .validFrom(T.minusSeconds(60))
                .validUntil(T.plusSeconds(3600))
                .created(T.minusSeconds(120))
                .createdBy("admin@example.com")
                .updated(T)
                .build());
    }

    @Test
    void fromThePlatformTenant_everyTenantButThePlatform_isQueried_andMergedNewestFirst() {
        IssuanceQuery query = query(Set.of(), null, 3, null);
        Issuance a1 = issuance(T.plusSeconds(5));
        Issuance a2 = issuance(T.plusSeconds(1));
        Issuance b1 = issuance(T.plusSeconds(4));
        Issuance b2 = issuance(T.plusSeconds(3));
        Issuance b3 = issuance(T.plusSeconds(2));
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of(PLATFORM_TENANT, "tenant-a", "tenant-b")));
        Map<String, Flux<Issuance>> byTenant = Map.of("tenant-a", Flux.just(a1, a2), "tenant-b", Flux.just(b1, b2, b3));
        List<String> queried = stubPerTenant(query, byTenant);

        IssuanceList page = service.list(platformAdmin(), query).block();

        assertThat(queried).containsExactlyInAnyOrder("tenant-a", "tenant-b");
        assertThat(page.issuances()).extracting(IssuanceSummary::id, IssuanceSummary::tenant).containsExactly(
                org.assertj.core.groups.Tuple.tuple(a1.getIssuanceId(), "tenant-a"),
                org.assertj.core.groups.Tuple.tuple(b1.getIssuanceId(), "tenant-b"),
                org.assertj.core.groups.Tuple.tuple(b2.getIssuanceId(), "tenant-b"));
        assertThat(PageCursor.decode(page.nextCursor()).orElseThrow().position()).isEqualTo(PagePosition.of(b2));
    }

    @Test
    void fromThePlatformTenant_theTenantFilter_queriesOnlyThatTenant() {
        IssuanceQuery query = query(Set.of(), "tenant-b", 50, null);
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of(PLATFORM_TENANT, "tenant-a", "tenant-b")));
        List<String> queried = stubPerTenant(query, Map.of("tenant-b", Flux.just(issuance(T))));

        IssuanceList page = service.list(platformAdmin(), query).block();

        assertThat(queried).containsExactly("tenant-b");
        assertThat(page.issuances()).extracting(IssuanceSummary::tenant).containsExactly("tenant-b");
    }

    @Test
    void fromThePlatformTenant_aTenantThatIsNotActive_isAnInvalidQuery() {
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of(PLATFORM_TENANT, "tenant-a")));

        StepVerifier.create(service.list(platformAdmin(), query(Set.of(), PLATFORM_TENANT, 50, null)))
                .expectError(InvalidQueryException.class)
                .verify();
        verify(issuancePort, never()).findPage(any(), any(), anyInt());
    }

    @Test
    void fromThePlatformTenant_aTenantThatFails_failsThePage() {
        IssuanceQuery query = query(Set.of(), null, 50, null);
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("tenant-a", "tenant-b")));
        stubPerTenant(query, Map.of(
                "tenant-a", Flux.just(issuance(T)),
                "tenant-b", Flux.error(new IllegalStateException("schema down"))));

        StepVerifier.create(service.list(platformAdmin(), query))
                .expectError(IllegalStateException.class)
                .verify();
    }

    @Test
    void theDetail_ofAnOrganizationAdmin_isLookedUpInItsOrganization_withTheAttestationData() {
        Issuance issuance = issuance(T);
        issuance.setOrganizationIdentifier("ORG-A");
        issuance.setCredentialType("doctor.sd.1");
        issuance.setCredentialDataSet("{\"given_name\":\"Ana\"}");
        when(issuancePort.findByIssuanceIdAndOrganizationIdentifier(issuance.getIssuanceId(), "ORG-A"))
                .thenReturn(Mono.just(issuance));

        IssuanceDetail detail = service.detail(organizationAdmin("ORG-A"), issuance.getIssuanceId()).block();

        assertThat(detail.summary()).isEqualTo(IssuanceSummary.builder()
                .id(issuance.getIssuanceId())
                .organizationIdentifier("ORG-A")
                .credentialConfigurationId("doctor.sd.1")
                .lifeCycleStatus("VALID")
                .updated(T)
                .build());
        assertThat(detail.credential().path("given_name").asText()).isEqualTo("Ana");
        verify(issuancePort, never()).findByIssuanceId(any());
    }

    @Test
    void theDetail_ofATenantAdmin_isLookedUpInTheWholeTenant() {
        Issuance issuance = issuance(T);
        issuance.setCredentialDataSet("{}");
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));

        StepVerifier.create(service.detail(tenantAdmin(), issuance.getIssuanceId()))
                .assertNext(detail -> assertThat(detail.summary().tenant()).isNull())
                .verifyComplete();
        verify(issuancePort, never()).findByIssuanceIdAndOrganizationIdentifier(any(), any());
    }

    @Test
    void theDetail_outOfScopeOrUnknown_isNotFound() {
        UUID id = UUID.randomUUID();
        when(issuancePort.findByIssuanceIdAndOrganizationIdentifier(id, "ORG-A")).thenReturn(Mono.empty());
        when(issuancePort.findByIssuanceId(id)).thenReturn(Mono.empty());

        StepVerifier.create(service.detail(organizationAdmin("ORG-A"), id))
                .expectError(IssuanceNotFoundException.class)
                .verify();
        StepVerifier.create(service.detail(tenantAdmin(), id))
                .expectError(IssuanceNotFoundException.class)
                .verify();
    }

    @Test
    void theDetail_fromThePlatformTenant_isLookedUpInEveryTenantButThePlatform_andSaysWhichOne() {
        Issuance issuance = issuance(T);
        issuance.setCredentialDataSet("{}");
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of(PLATFORM_TENANT, "tenant-a", "tenant-b")));
        List<String> queried = java.util.Collections.synchronizedList(new ArrayList<>());
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenAnswer(invocation ->
                Mono.deferContextual(ctx -> {
                    String tenant = ctx.get(TENANT_DOMAIN_CONTEXT_KEY);
                    queried.add(tenant);
                    return "tenant-b".equals(tenant) ? Mono.just(issuance) : Mono.empty();
                }));

        IssuanceDetail detail = service.detail(platformAdmin(), issuance.getIssuanceId()).block();

        assertThat(detail.summary().tenant()).isEqualTo("tenant-b");
        assertThat(queried).containsExactly("tenant-a", "tenant-b");
        verify(issuancePort, never()).findByIssuanceIdAndOrganizationIdentifier(any(), any());
    }

    @Test
    void theDetail_fromThePlatformTenant_inNoTenant_isNotFound() {
        UUID id = UUID.randomUUID();
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("tenant-a", "tenant-b")));
        when(issuancePort.findByIssuanceId(id)).thenReturn(Mono.empty());

        StepVerifier.create(service.detail(platformAdmin(), id))
                .expectError(IssuanceNotFoundException.class)
                .verify();
    }

    @Test
    void theDetail_ofAProcessWhoseAttestationDataIsNotJson_fails() {
        Issuance broken = issuance(T);
        broken.setCredentialDataSet("{\"given_name\":");
        Issuance empty = issuance(T);
        when(issuancePort.findByIssuanceId(broken.getIssuanceId())).thenReturn(Mono.just(broken));
        when(issuancePort.findByIssuanceId(empty.getIssuanceId())).thenReturn(Mono.just(empty));

        StepVerifier.create(service.detail(tenantAdmin(), broken.getIssuanceId()))
                .expectError(ParseCredentialJsonException.class)
                .verify();
        StepVerifier.create(service.detail(tenantAdmin(), empty.getIssuanceId()))
                .expectError(ParseCredentialJsonException.class)
                .verify();
    }

    /** EUD-244: a detail that is returned leaves one access, with the holder in clear, in the request's tenant. */
    @Test
    void theDetail_isAudited_withTheHolderInClear() {
        Issuance issuance = issuance(T);
        issuance.setCredentialDataSet("{\"vc\":{}}");
        issuance.setSubject("Jane Doe");
        issuance.setEmail("jane@example.com");
        when(issuancePort.findByIssuanceIdAndOrganizationIdentifier(issuance.getIssuanceId(), "ORG-A"))
                .thenReturn(Mono.just(issuance));

        service.detail(organizationAdmin("ORG-A"), issuance.getIssuanceId()).block();

        assertThat(auditTrail.all()).singleElement().satisfies(entry -> {
            assertThat(entry.type()).isEqualTo(AuditEventType.ISSUANCE_DETAIL_ACCESSED);
            assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
            assertThat(entry.resource()).isEqualTo("issuance:" + issuance.getIssuanceId());
            assertThat(entry.details()).containsEntry("holder", Map.of("name", "Jane Doe", "email", "jane@example.com"));
        });
        assertThat(auditTrail.tenantScopes()).isEmpty();
    }

    /** EUD-244 D62: a platform administrator's read is staged once, under the tenant that owns the process. */
    @Test
    void theDetail_fromThePlatformTenant_isAuditedOnceUnderTheTenantOfTheProcess() {
        Issuance issuance = issuance(T);
        issuance.setCredentialDataSet("{}");
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("acme")));
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));

        service.detail(platformAdmin(), issuance.getIssuanceId()).block();

        assertThat(auditTrail.all()).hasSize(1);
        assertThat(auditTrail.tenantScopes()).containsExactly("acme");
    }

    /** EUD-244: a detail that is not found leaves a Denied IssuanceNotFound, and the error goes on. */
    @Test
    void theDetail_notFound_isAuditedAsDenied_andKeepsTheError() {
        UUID id = UUID.randomUUID();
        when(issuancePort.findByIssuanceIdAndOrganizationIdentifier(id, "ORG-A")).thenReturn(Mono.empty());

        StepVerifier.create(service.detail(organizationAdmin("ORG-A"), id))
                .expectError(IssuanceNotFoundException.class)
                .verify();

        assertThat(auditTrail.all()).singleElement().satisfies(entry -> {
            assertThat(entry.result()).isEqualTo(AuditResult.DENIED);
            assertThat(entry.reason()).isEqualTo("IssuanceNotFound");
        });
    }

    /** Answers each tenant's rows according to the tenant in the Reactor context, and records which were asked. */
    private List<String> stubPerTenant(IssuanceQuery query, Map<String, Flux<Issuance>> byTenant) {
        List<String> queried = java.util.Collections.synchronizedList(new ArrayList<>());
        Map<String, Flux<Issuance>> rows = new ConcurrentHashMap<>(byTenant);
        when(issuancePort.findPage(eq(query), isNull(), eq(query.limit() + 1))).thenAnswer(invocation ->
                Flux.deferContextual(ctx -> {
                    String tenant = ctx.get(TENANT_DOMAIN_CONTEXT_KEY);
                    queried.add(tenant);
                    return rows.getOrDefault(tenant, Flux.empty());
                }));
        return queried;
    }

    private static IssuanceQuery query(Set<CredentialStatusEnum> states, String tenant, int limit, PageCursor cursor) {
        return new IssuanceQuery(states, null, tenant, limit, cursor);
    }

    private static Issuance issuance(Instant lastChangedAt) {
        return Issuance.builder()
                .issuanceId(UUID.randomUUID())
                .credentialStatus(CredentialStatusEnum.VALID)
                .lastChangedAt(lastChangedAt)
                .build();
    }

    private static AuthorizationDecision organizationAdmin(String organization) {
        return TestAuthorizationDecisions.query(organization, UserRole.LEAR, false);
    }

    private static AuthorizationDecision tenantAdmin() {
        return TestAuthorizationDecisions.query("ORG-ADMIN", UserRole.TENANT_ADMIN, false);
    }

    private static AuthorizationDecision platformAdmin() {
        return TestAuthorizationDecisions.query("ORG-PLATFORM", UserRole.SYSADMIN, true);
    }
}
