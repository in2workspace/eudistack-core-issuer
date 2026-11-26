package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.AuditTrailUnavailableException;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceQueryUnavailableException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.exception.TenantSecretKeyUnavailableException;
import es.in2.issuer.backend.shared.domain.exception.UnknownIdentifierTypeException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.query.SearchIdentifierCriterion;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprinter;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
import org.mockito.ArgumentCaptor;
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
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
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

import java.nio.charset.StandardCharsets;
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
    private PowerAuthorizationService powerAuthorizationService;
    private RecordingAuditTrail auditTrail;
    private CatalogEntryPort catalogEntryPort;
    private TenantSecretKeyPort tenantSecretKeyPort;
    private IssuanceQueryServiceImpl service;

    @BeforeEach
    void setUp() {
        issuancePort = mock(IssuancePort.class);
        tenantRegistryService = mock(TenantRegistryService.class);
        auditTrail = new RecordingAuditTrail();
        powerAuthorizationService = mock(PowerAuthorizationService.class);
        catalogEntryPort = mock(CatalogEntryPort.class);
        tenantSecretKeyPort = mock(TenantSecretKeyPort.class);
        service = new IssuanceQueryServiceImpl(issuancePort, tenantRegistryService, powerAuthorizationService,
                auditTrail, new ObjectMapper(), catalogEntryPort, tenantSecretKeyPort);
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
                .expectError(IssuanceQueryUnavailableException.class)
                .verify();
        assertThat(auditTrail.all()).isEmpty();
    }

    /** AD-3, ES-01: a schema that fails is internal_error, from any tenant, and nothing is returned or traced. */
    @Test
    void aSchemaThatFails_isAnUnavailableQuery() {
        IssuanceQuery query = query(Set.of(), null, 50, null);
        when(issuancePort.findPage(query, "ORG-A", 51)).thenReturn(Flux.error(new IllegalStateException("schema down")));

        StepVerifier.create(service.list(organizationAdmin("ORG-A"), query))
                .expectError(IssuanceQueryUnavailableException.class)
                .verify();
        assertThat(auditTrail.all()).isEmpty();
    }

    @Test
    void fromThePlatformTenant_aRegistryThatFails_isAnUnavailableQuery() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.error(new IllegalStateException("registry down")));

        StepVerifier.create(service.list(platformAdmin(), query(Set.of(), null, 50, null)))
                .expectError(IssuanceQueryUnavailableException.class)
                .verify();
    }

    /** A detail that cannot be read is not a refusal: it is internal_error and leaves no Denied. */
    @Test
    void aDetailThatCannotBeRead_isAnUnavailableQuery_andNoRefusal() {
        UUID id = UUID.randomUUID();
        when(issuancePort.findByIssuanceId(id)).thenReturn(Mono.error(new IllegalStateException("schema down")));

        StepVerifier.create(service.detail(id))
                .expectError(IssuanceQueryUnavailableException.class)
                .verify();
        assertThat(auditTrail.all()).isEmpty();
        verifyNoInteractions(powerAuthorizationService);
    }

    /** AD-7: the trace carries the filters as the request gave them, by their names in the API. */
    @Test
    void eachPage_isAudited_withTheFiltersItWasAskedWith() {
        IssuanceQuery query = new IssuanceQuery(Set.of(CredentialStatusEnum.VALID, CredentialStatusEnum.DRAFT),
                "doctor.sd.1", null, 50, null);
        when(issuancePort.findPage(query, "ORG-A", 51)).thenReturn(Flux.empty());

        service.list(organizationAdmin("ORG-A"), query).block();

        assertThat(auditTrail.stagedInNewTransaction()).singleElement().satisfies(entry ->
                assertThat(entry.details()).containsEntry("filters", Map.of(
                        "life_cycle_status", List.of("DRAFT", "VALID"),
                        "credential_configuration_id", "doctor.sd.1")));
    }

    /** AD-7: a page that cannot be traced is not returned. */
    @Test
    void aPageThatCannotBeAudited_isNotReturned() {
        auditTrail.failingOnNewTransaction();
        IssuanceQuery query = query(Set.of(), null, 50, null);
        when(issuancePort.findPage(query, "ORG-A", 51)).thenReturn(Flux.just(issuance(T)));

        StepVerifier.create(service.list(organizationAdmin("ORG-A"), query))
                .expectError(AuditTrailUnavailableException.class)
                .verify();
    }

    @Test
    void theDetail_isDecidedOnTheOrganizationStoredWithTheProcess() {
        Issuance stored = issuance(T);
        stored.setOrganizationIdentifier("ORG-B");
        stored.setCredentialDataSet("{}");
        UUID unknown = UUID.randomUUID();
        when(issuancePort.findByIssuanceId(stored.getIssuanceId())).thenReturn(Mono.just(stored));
        when(issuancePort.findByIssuanceId(unknown)).thenReturn(Mono.empty());
        decidedAs(tenantAdmin());

        service.detail(stored.getIssuanceId()).block();
        StepVerifier.create(service.detail(unknown)).expectError(IssuanceNotFoundException.class).verify();

        verify(powerAuthorizationService).authorizeQuery("ORG-B", stored.getIssuanceId().toString());
        verify(powerAuthorizationService).authorizeQuery(null, unknown.toString());
    }

    @Test
    void theDetail_ofAnOrganizationAdmin_isLookedUpInItsOrganization_withTheAttestationData() {
        Issuance issuance = issuance(T);
        issuance.setOrganizationIdentifier("ORG-A");
        issuance.setCredentialType("doctor.sd.1");
        issuance.setCredentialDataSet("{\"given_name\":\"Ana\"}");
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.findByIssuanceIdAndOrganizationIdentifier(issuance.getIssuanceId(), "ORG-A"))
                .thenReturn(Mono.just(issuance));
        decidedAs(organizationAdmin("ORG-A"));

        IssuanceDetail detail = service.detail(issuance.getIssuanceId()).block();

        assertThat(detail.summary()).isEqualTo(IssuanceSummary.builder()
                .id(issuance.getIssuanceId())
                .organizationIdentifier("ORG-A")
                .credentialConfigurationId("doctor.sd.1")
                .lifeCycleStatus("VALID")
                .updated(T)
                .build());
        assertThat(detail.credential().path("given_name").asText()).isEqualTo("Ana");
        verify(issuancePort).findByIssuanceIdAndOrganizationIdentifier(issuance.getIssuanceId(), "ORG-A");
    }

    @Test
    void theDetail_ofATenantAdmin_isLookedUpInTheWholeTenant() {
        Issuance issuance = issuance(T);
        issuance.setCredentialDataSet("{}");
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        decidedAs(tenantAdmin());

        StepVerifier.create(service.detail(issuance.getIssuanceId()))
                .assertNext(detail -> assertThat(detail.summary().tenant()).isNull())
                .verifyComplete();
        verify(issuancePort, never()).findByIssuanceIdAndOrganizationIdentifier(any(), any());
    }

    @Test
    void theDetail_outOfScopeOrUnknown_isNotFound() {
        UUID id = UUID.randomUUID();
        when(issuancePort.findByIssuanceIdAndOrganizationIdentifier(id, "ORG-A")).thenReturn(Mono.empty());
        when(issuancePort.findByIssuanceId(id)).thenReturn(Mono.empty());

        decidedAs(organizationAdmin("ORG-A"));
        StepVerifier.create(service.detail(id))
                .expectError(IssuanceNotFoundException.class)
                .verify();
        decidedAs(tenantAdmin());
        StepVerifier.create(service.detail(id))
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
                    String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, PLATFORM_TENANT);
                    queried.add(tenant);
                    return "tenant-b".equals(tenant) ? Mono.just(issuance) : Mono.empty();
                }));
        decidedAs(platformAdmin());

        IssuanceDetail detail = service.detail(issuance.getIssuanceId()).block();

        assertThat(detail.summary().tenant()).isEqualTo("tenant-b");
        // First the organization stored with it in the request's tenant, then every other tenant in order.
        assertThat(queried).containsExactly(PLATFORM_TENANT, "tenant-a", "tenant-b");
        verify(issuancePort, never()).findByIssuanceIdAndOrganizationIdentifier(any(), any());
    }

    @Test
    void theDetail_fromThePlatformTenant_inNoTenant_isNotFound() {
        UUID id = UUID.randomUUID();
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("tenant-a", "tenant-b")));
        when(issuancePort.findByIssuanceId(id)).thenReturn(Mono.empty());
        decidedAs(platformAdmin());

        StepVerifier.create(service.detail(id))
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
        decidedAs(tenantAdmin());

        StepVerifier.create(service.detail(broken.getIssuanceId()))
                .expectError(ParseCredentialJsonException.class)
                .verify();
        StepVerifier.create(service.detail(empty.getIssuanceId()))
                .expectError(ParseCredentialJsonException.class)
                .verify();
        assertThat(auditTrail.all()).isEmpty();
    }

    /** EUD-244: a detail that is returned leaves one access, with the holder in clear, in the request's tenant. */
    @Test
    void theDetail_isAudited_withTheHolderInClear() {
        Issuance issuance = issuance(T);
        issuance.setOrganizationIdentifier("ORG-A");
        issuance.setCredentialDataSet("{\"vc\":{}}");
        issuance.setSubject("Jane Doe");
        issuance.setEmail("jane@example.com");
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        when(issuancePort.findByIssuanceIdAndOrganizationIdentifier(issuance.getIssuanceId(), "ORG-A"))
                .thenReturn(Mono.just(issuance));
        decidedAs(organizationAdmin("ORG-A"));

        service.detail(issuance.getIssuanceId()).block();

        assertThat(auditTrail.stagedInNewTransaction()).singleElement().satisfies(entry -> {
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
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenAnswer(invocation ->
                Mono.deferContextual(ctx -> ctx.hasKey(TENANT_DOMAIN_CONTEXT_KEY) ? Mono.just(issuance) : Mono.empty()));
        decidedAs(platformAdmin());

        service.detail(issuance.getIssuanceId()).block();

        assertThat(auditTrail.all()).hasSize(1);
        assertThat(auditTrail.tenantScopes()).containsExactly("acme");
    }

    /** AD-8: a detail that is not found leaves a Denied IssuanceNotFound, and the error goes on. */
    @Test
    void theDetail_notFound_isAuditedAsDenied_andKeepsTheError() {
        UUID id = UUID.randomUUID();
        when(issuancePort.findByIssuanceId(id)).thenReturn(Mono.empty());
        when(issuancePort.findByIssuanceIdAndOrganizationIdentifier(id, "ORG-A")).thenReturn(Mono.empty());
        decidedAs(organizationAdmin("ORG-A"));

        StepVerifier.create(service.detail(id))
                .expectError(IssuanceNotFoundException.class)
                .verify();

        assertThat(auditTrail.stagedInNewTransaction()).singleElement().satisfies(entry -> {
            assertThat(entry.result()).isEqualTo(AuditResult.DENIED);
            assertThat(entry.reason()).isEqualTo("IssuanceNotFound");
        });
    }

    /** AC-08: a process of another organization reads, and is traced, as one that does not exist. */
    @Test
    void theDetail_outOfScope_isAuditedAsNotFound() {
        Issuance other = issuance(T);
        other.setOrganizationIdentifier("ORG-B");
        when(issuancePort.findByIssuanceId(other.getIssuanceId())).thenReturn(Mono.just(other));
        when(powerAuthorizationService.authorizeQuery("ORG-B", other.getIssuanceId().toString()))
                .thenReturn(Mono.error(new IssuanceNotFoundException("No issuance found for the given id")));

        StepVerifier.create(service.detail(other.getIssuanceId()))
                .expectError(IssuanceNotFoundException.class)
                .verify();

        assertThat(auditTrail.stagedInNewTransaction()).singleElement().satisfies(entry -> {
            assertThat(entry.type()).isEqualTo(AuditEventType.ISSUANCE_DETAIL_ACCESSED);
            assertThat(entry.reason()).isEqualTo("IssuanceNotFound");
            assertThat(entry.details()).isEmpty();
        });
    }

    /** ES-05: who may not read processes is refused, and the refusal is traced as PolicyDenied. */
    @Test
    void theDetail_withoutThePermission_isAuditedAsPolicyDenied_andKeepsTheError() {
        UUID id = UUID.randomUUID();
        when(issuancePort.findByIssuanceId(id)).thenReturn(Mono.empty());
        when(powerAuthorizationService.authorizeQuery(any(), any())).thenReturn(Mono.error(
                new LearIssuancePolicyException(LearIssuancePolicyException.Reason.OPERATOR_LACKS_ONBOARDING, "denied")));

        StepVerifier.create(service.detail(id))
                .expectError(LearIssuancePolicyException.class)
                .verify();

        assertThat(auditTrail.stagedInNewTransaction()).singleElement().satisfies(entry -> {
            assertThat(entry.result()).isEqualTo(AuditResult.DENIED);
            assertThat(entry.reason()).isEqualTo("PolicyDenied");
        });
        verify(issuancePort, never()).findByIssuanceIdAndOrganizationIdentifier(any(), any());
    }

    /** AD-7, AC-10: a detail whose access cannot be traced is not returned. */
    @Test
    void aDetailThatCannotBeAudited_isNotReturned() {
        auditTrail.failingOnNewTransaction();
        Issuance issuance = issuance(T);
        issuance.setCredentialDataSet("{\"given_name\":\"Ana\"}");
        when(issuancePort.findByIssuanceId(issuance.getIssuanceId())).thenReturn(Mono.just(issuance));
        decidedAs(tenantAdmin());

        StepVerifier.create(service.detail(issuance.getIssuanceId()))
                .expectError(AuditTrailUnavailableException.class)
                .verify();
    }

    /** ES-06: a refusal that cannot be traced fails as the trail, never saying why it was refused. */
    @Test
    void aRefusalThatCannotBeAudited_failsWithoutItsReason() {
        auditTrail.failingOnNewTransaction();
        UUID id = UUID.randomUUID();
        when(issuancePort.findByIssuanceId(id)).thenReturn(Mono.empty());
        decidedAs(tenantAdmin());

        StepVerifier.create(service.detail(id))
                .expectError(AuditTrailUnavailableException.class)
                .verify();

        when(powerAuthorizationService.authorizeQuery(any(), any())).thenReturn(Mono.error(
                new LearIssuancePolicyException(LearIssuancePolicyException.Reason.OPERATOR_LACKS_ONBOARDING, "denied")));
        StepVerifier.create(service.detail(id))
                .expectError(AuditTrailUnavailableException.class)
                .verify();
    }

    // ---- search by identifier (FR-05, AD-4, AD-5) ------------------------------------------------------------

    private static final String TENANT_X = "tenant-x";
    private static final byte[] KEY = "a-tenant-secret-key-of-32-bytes!".getBytes(StandardCharsets.UTF_8);
    private static final CatalogEntry.SearchIdentifier COLEGIADO =
            new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("credentialSubject", "colegiado"));
    private static final CatalogEntry.SearchIdentifier DNI =
            new CatalogEntry.SearchIdentifier("dni", ClaimPath.of("credentialSubject", "dni"));

    /** AC-05: the value is fingerprinted with the tenant key and the page is searched by that fingerprint. */
    @Test
    void aSearchByIdentifier_findsByItsFingerprintWithTheTenantKey_neverByItsValue() {
        IssuanceQuery query = byIdentifier("colegiado", "28 / 12345", null);
        catalogDeclares(entry("doctor.sd.1", List.of(DNI)), entry("colegio.sd.1", List.of(COLEGIADO)));
        when(tenantSecretKeyPort.keyOf(TENANT_X)).thenReturn(Mono.just(KEY));
        Issuance found = issuance(T);
        when(issuancePort.findPage(any(), eq("ORG-A"), eq(51))).thenReturn(Flux.just(found));

        IssuanceList page = inTenant(service.list(organizationAdmin("ORG-A"), query)).block();

        assertThat(page.issuances()).extracting(IssuanceSummary::id).containsExactly(found.getIssuanceId());
        ArgumentCaptor<IssuanceQuery> searched = ArgumentCaptor.forClass(IssuanceQuery.class);
        verify(issuancePort).findPage(searched.capture(), eq("ORG-A"), eq(51));
        assertThat(searched.getValue().identifier().value()).isNull();
        assertThat(searched.getValue().identifier()).isEqualTo(SearchIdentifierCriterion.searched("colegiado", "x")
                .fingerprinted(SearchIdentifierFingerprinter.fingerprint(KEY, "28/12345").orElseThrow()));
    }

    /** AD-7: the trace carries the identifier as received, the one place it is kept. */
    @Test
    void aSearchByIdentifier_isTracedWithTheValueAsReceived() {
        catalogDeclares(entry("colegio.sd.1", List.of(COLEGIADO)));
        when(tenantSecretKeyPort.keyOf(TENANT_X)).thenReturn(Mono.just(KEY));
        when(issuancePort.findPage(any(), eq("ORG-A"), eq(51))).thenReturn(Flux.empty());

        inTenant(service.list(organizationAdmin("ORG-A"), byIdentifier("colegiado", "28 / 12345", null))).block();

        assertThat(auditTrail.stagedInNewTransaction()).singleElement().satisfies(entry -> {
            assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
            assertThat(entry.details()).containsEntry("filters",
                    Map.of("identifier_type", "colegiado", "identifier", "28 / 12345"));
        });
    }

    /** A value that normalizes to nothing has no fingerprint: it finds no process. */
    @Test
    void aValueWithoutCharacters_searchesAFingerprintNoProcessHas() {
        catalogDeclares(entry("colegio.sd.1", List.of(COLEGIADO)));
        when(tenantSecretKeyPort.keyOf(TENANT_X)).thenReturn(Mono.just(KEY));
        when(issuancePort.findPage(any(), eq("ORG-A"), eq(51))).thenReturn(Flux.empty());

        inTenant(service.list(organizationAdmin("ORG-A"), byIdentifier("colegiado", " ", null))).block();

        ArgumentCaptor<IssuanceQuery> searched = ArgumentCaptor.forClass(IssuanceQuery.class);
        verify(issuancePort).findPage(searched.capture(), eq("ORG-A"), eq(51));
        assertThat(searched.getValue().identifier().fingerprint()).isEmpty();
    }

    /** AC-06: a type no entry of the tenant declares is refused, traced first, without reading the key. */
    @Test
    void aTypeNoEntryDeclares_isAnUnknownIdentifierType_tracedAsDenied() {
        catalogDeclares(entry("doctor.sd.1", List.of(DNI)), entry("plain.sd.1", List.of()));

        StepVerifier.create(inTenant(service.list(organizationAdmin("ORG-A"), byIdentifier("colegiado", "28/12345", null))))
                .expectError(UnknownIdentifierTypeException.class)
                .verify();

        assertThat(auditTrail.stagedInNewTransaction()).singleElement().satisfies(entry -> {
            assertThat(entry.type()).isEqualTo(AuditEventType.ISSUANCE_QUERIED);
            assertThat(entry.result()).isEqualTo(AuditResult.DENIED);
            assertThat(entry.reason()).isEqualTo("UnknownIdentifierType");
            assertThat(entry.details()).containsEntry("filters",
                    Map.of("identifier_type", "colegiado", "identifier", "28/12345"));
        });
        verifyNoInteractions(tenantSecretKeyPort, issuancePort);
    }

    /** AD-7: a refusal that cannot be traced is internal_error. */
    @Test
    void anUnknownIdentifierType_thatCannotBeTraced_isAnUnavailableTrail() {
        auditTrail.failingOnNewTransaction();
        catalogDeclares(entry("doctor.sd.1", List.of(DNI)));

        StepVerifier.create(inTenant(service.list(organizationAdmin("ORG-A"), byIdentifier("colegiado", "28/12345", null))))
                .expectError(AuditTrailUnavailableException.class)
                .verify();
    }

    /** ES-03: a catalogue that cannot be read is internal_error, and nothing is searched nor traced. */
    @Test
    void aCatalogueThatCannotBeRead_isAnUnavailableQuery() {
        when(catalogEntryPort.findAll()).thenReturn(Flux.error(new IllegalStateException("catalogue down")));

        StepVerifier.create(inTenant(service.list(organizationAdmin("ORG-A"), byIdentifier("colegiado", "28/12345", null))))
                .expectError(IssuanceQueryUnavailableException.class)
                .verify();
        assertThat(auditTrail.all()).isEmpty();
        verifyNoInteractions(issuancePort);
    }

    /** ES-02: a tenant key that cannot be read is internal_error, and nothing is searched nor traced. */
    @Test
    void aTenantKeyThatCannotBeRead_isAnUnavailableQuery() {
        catalogDeclares(entry("colegio.sd.1", List.of(COLEGIADO)));
        when(tenantSecretKeyPort.keyOf(TENANT_X))
                .thenReturn(Mono.error(new TenantSecretKeyUnavailableException("no key")));

        StepVerifier.create(inTenant(service.list(organizationAdmin("ORG-A"), byIdentifier("colegiado", "28/12345", null))))
                .expectError(IssuanceQueryUnavailableException.class)
                .verify();
        assertThat(auditTrail.all()).isEmpty();
        verifyNoInteractions(issuancePort);
    }

    /** ES-02: the listing and the search by name need neither the catalogue nor the key. */
    @Test
    void theListingAndTheSearchByName_needNeitherTheCatalogueNorTheKey() {
        when(issuancePort.findPage(any(), eq("ORG-A"), eq(51))).thenReturn(Flux.empty());

        inTenant(service.list(organizationAdmin("ORG-A"), query(Set.of(), null, 50, null))).block();
        inTenant(service.list(organizationAdmin("ORG-A"), new IssuanceQuery(Set.of(), null, null, 50, null, "garcia"))).block();

        verifyNoInteractions(catalogEntryPort, tenantSecretKeyPort);
    }

    /** AC-12: from the platform tenant the search by identifier names the tenant it searches in. */
    @Test
    void fromThePlatformTenant_aSearchByIdentifier_withoutTenant_isAnInvalidQuery() {
        StepVerifier.create(service.list(platformAdmin(), byIdentifier("colegiado", "28/12345", null)))
                .expectErrorSatisfies(error -> assertThat(((InvalidQueryException) error).violations())
                        .extracting(InvalidQueryException.Violation::field).containsExactly("tenant"))
                .verify();
        verifyNoInteractions(catalogEntryPort, tenantSecretKeyPort, issuancePort, tenantRegistryService);
    }

    @Test
    void fromThePlatformTenant_aSearchByIdentifier_inATenantThatIsNotActive_isAnInvalidQuery() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of(PLATFORM_TENANT, "tenant-a")));

        StepVerifier.create(service.list(platformAdmin(), byIdentifier("colegiado", "28/12345", "tenant-b")))
                .expectErrorSatisfies(error -> assertThat(((InvalidQueryException) error).violations())
                        .extracting(InvalidQueryException.Violation::field).containsExactly("tenant"))
                .verify();
        verifyNoInteractions(catalogEntryPort, tenantSecretKeyPort, issuancePort);
    }

    /** AC-12, AD-4: from the platform tenant, the catalogue, the key and the processes are those of the tenant named. */
    @Test
    void fromThePlatformTenant_aSearchByIdentifier_usesTheCatalogueAndTheKeyOfTheTenantNamed() {
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of(PLATFORM_TENANT, "tenant-a", "tenant-b")));
        List<String> catalogueOf = java.util.Collections.synchronizedList(new ArrayList<>());
        when(catalogEntryPort.findAll()).thenAnswer(invocation -> Flux.deferContextual(ctx -> {
            catalogueOf.add(ctx.get(TENANT_DOMAIN_CONTEXT_KEY));
            return Flux.just(entry("colegio.sd.1", List.of(COLEGIADO)));
        }));
        when(tenantSecretKeyPort.keyOf("tenant-b")).thenReturn(Mono.just(KEY));
        Issuance found = issuance(T);
        List<String> queried = java.util.Collections.synchronizedList(new ArrayList<>());
        when(issuancePort.findPage(any(), isNull(), eq(51))).thenAnswer(invocation -> Flux.deferContextual(ctx -> {
            queried.add(ctx.get(TENANT_DOMAIN_CONTEXT_KEY));
            return Flux.just(found);
        }));

        IssuanceList page = service.list(platformAdmin(), byIdentifier("colegiado", "28/12345", "tenant-b"))
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, PLATFORM_TENANT))
                .block();

        assertThat(catalogueOf).containsExactly("tenant-b");
        assertThat(queried).containsExactly("tenant-b");
        assertThat(page.issuances()).extracting(IssuanceSummary::id, IssuanceSummary::tenant)
                .containsExactly(org.assertj.core.groups.Tuple.tuple(found.getIssuanceId(), "tenant-b"));
        verify(tenantSecretKeyPort).keyOf("tenant-b");
    }

    /** The cursor of a search by identifier serves that identifier only: its digest is that of its fingerprint. */
    @Test
    void theCursorOfASearchByIdentifier_servesOnlyThatIdentifier() {
        catalogDeclares(entry("colegio.sd.1", List.of(COLEGIADO)));
        when(tenantSecretKeyPort.keyOf(TENANT_X)).thenReturn(Mono.just(KEY));
        when(issuancePort.findPage(any(), eq("ORG-A"), eq(2))).thenReturn(Flux.just(issuance(T.plusSeconds(2)), issuance(T)));
        IssuanceQuery first = new IssuanceQuery(Set.of(), null, null, 1, null, null,
                SearchIdentifierCriterion.searched("colegiado", "28/12345"));
        String cursor = inTenant(service.list(organizationAdmin("ORG-A"), first)).block().nextCursor();

        IssuanceQuery sameWrittenOtherwise = new IssuanceQuery(Set.of(), null, null, 1,
                PageCursor.decode(cursor).orElseThrow(), null, SearchIdentifierCriterion.searched("colegiado", "28 / 12345"));
        IssuanceQuery other = new IssuanceQuery(Set.of(), null, null, 1,
                PageCursor.decode(cursor).orElseThrow(), null, SearchIdentifierCriterion.searched("colegiado", "28/99999"));

        StepVerifier.create(inTenant(service.list(organizationAdmin("ORG-A"), sameWrittenOtherwise))).expectNextCount(1).verifyComplete();
        StepVerifier.create(inTenant(service.list(organizationAdmin("ORG-A"), other)))
                .expectErrorSatisfies(error -> assertThat(((InvalidQueryException) error).violations())
                        .extracting(InvalidQueryException.Violation::field).containsExactly("cursor"))
                .verify();
    }

    private void catalogDeclares(CatalogEntry... entries) {
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(entries));
    }

    private static CatalogEntry entry(String id, List<CatalogEntry.SearchIdentifier> identifiers) {
        return new CatalogEntry(id, "https://schema", true, null, null, null, identifiers, 1, null, null);
    }

    private static IssuanceQuery byIdentifier(String type, String value, String tenant) {
        return new IssuanceQuery(Set.of(), null, tenant, 50, null, null, SearchIdentifierCriterion.searched(type, value));
    }

    private static <T> Mono<T> inTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT_X));
    }

    private void decidedAs(AuthorizationDecision decision) {
        when(powerAuthorizationService.authorizeQuery(any(), any())).thenReturn(Mono.just(decision));
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
