package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryChange;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.SYSTEM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CatalogEntryChangeAuditorTest {

    private static final String TENANT = "demo";
    private static final String PERSON = "jane.doe@example.org";
    private static final String ORGANIZATION = "VATES-A12345678";
    private static final String DOCTORID = "doctorid.sd.1";

    @Mock private AuditService auditService;
    @Mock private AccessTokenService accessTokenService;

    private CatalogEntryChangeAuditor auditor;

    @BeforeEach
    void setUp() {
        auditor = new CatalogEntryChangeAuditor(auditService, accessTokenService);
        when(accessTokenService.getOrganizationIdFromCurrentSession()).thenReturn(Mono.just(ORGANIZATION));
    }

    /** AC-12: the event says which person did it, and the organization goes next to it, not in the details. */
    @Test
    void audit_recordsThePersonOfTheTokenAsUser_notTheOrganization() {
        StepVerifier.create(asPersonInTenant(auditor.audit(CatalogEntryChange.updated(entry(true, 3), entry(false, 4)))))
                .verifyComplete();

        ArgumentCaptor<Map<String, Object>> details = detailsCaptor();
        verify(auditService).auditSuccess(eq("CatalogEntryChanged"), eq(PERSON), eq(ORGANIZATION),
                eq("attestation-catalog"), eq(TENANT), details.capture());
        assertThat(details.getValue()).doesNotContainKeys("organization_id", "organization");
        assertThat(details.getValue().values()).doesNotContain(PERSON);
    }

    @Test
    void audit_ofAnUpdate_carriesTheOperationTheEntryAndTheChanges() {
        StepVerifier.create(asPersonInTenant(auditor.audit(CatalogEntryChange.updated(entry(true, 3), entry(false, 4)))))
                .verifyComplete();

        ArgumentCaptor<Map<String, Object>> details = detailsCaptor();
        verify(auditService).auditSuccess(anyString(), anyString(), anyString(), anyString(), anyString(),
                details.capture());
        assertThat(details.getValue()).containsExactly(
                Map.entry("operation", "Update"),
                Map.entry("credential_configuration_id", DOCTORID),
                Map.entry("changes", Map.of("enabled", Arrays.asList(true, false))));
    }

    @Test
    void audit_ofAnEnable_hasNoChangesNorVersion() {
        StepVerifier.create(asPersonInTenant(auditor.audit(CatalogEntryChange.between(entry(false, 3), entry(true, 4)))))
                .verifyComplete();

        ArgumentCaptor<Map<String, Object>> details = detailsCaptor();
        verify(auditService).auditSuccess(anyString(), anyString(), anyString(), anyString(), anyString(),
                details.capture());
        assertThat(details.getValue()).containsExactly(
                Map.entry("operation", "Enable"),
                Map.entry("credential_configuration_id", DOCTORID));
    }

    @Test
    void audit_ofADisable_isNamedDisable() {
        StepVerifier.create(asPersonInTenant(auditor.audit(CatalogEntryChange.between(entry(true, 3), entry(false, 4)))))
                .verifyComplete();

        ArgumentCaptor<Map<String, Object>> details = detailsCaptor();
        verify(auditService).auditSuccess(anyString(), anyString(), anyString(), anyString(), anyString(),
                details.capture());
        assertThat(details.getValue()).containsEntry("operation", "Disable").doesNotContainKey("changes");
    }

    @Test
    void audit_ofACreate_hasNoChanges() {
        StepVerifier.create(asPersonInTenant(auditor.audit(CatalogEntryChange.created(entry(true, 0)))))
                .verifyComplete();

        ArgumentCaptor<Map<String, Object>> details = detailsCaptor();
        verify(auditService).auditSuccess(anyString(), anyString(), anyString(), anyString(), anyString(),
                details.capture());
        assertThat(details.getValue()).containsEntry("operation", "Create").doesNotContainKeys("changes", "version");
    }

    // ---- denied writes ---------------------------------------------------------

    @Test
    void auditDenied_recordsThePersonTheReasonAndWhatIsKnown() {
        StepVerifier.create(asPersonInTenant(auditor.auditDenied(
                        CatalogEntryChange.Operation.UPDATE, DOCTORID, CatalogEntryChangeAuditor.POLICY_DENIED)))
                .verifyComplete();

        ArgumentCaptor<Map<String, Object>> details = detailsCaptor();
        verify(auditService).auditFailure(eq("CatalogEntryChanged"), eq(PERSON), eq(ORGANIZATION), eq("PolicyDenied"),
                details.capture());
        assertThat(details.getValue()).containsExactly(
                Map.entry("operation", "Update"),
                Map.entry("credential_configuration_id", DOCTORID));
    }

    @Test
    void auditDenied_leavesOutWhatIsNotKnown() {
        StepVerifier.create(asPersonInTenant(auditor.auditDenied(
                        null, null, CatalogEntryChangeAuditor.INVALID_CONFIGURATION)))
                .verifyComplete();

        ArgumentCaptor<Map<String, Object>> details = detailsCaptor();
        verify(auditService).auditFailure(anyString(), anyString(), eq(ORGANIZATION), eq("InvalidConfiguration"),
                details.capture());
        assertThat(details.getValue()).isEmpty();
    }

    @Test
    void auditDenied_whenTheAuditChannelFails_doesNotFail() {
        doThrow(new IllegalStateException("audit down")).when(auditService)
                .auditFailure(anyString(), any(), any(), anyString(), any());

        StepVerifier.create(asPersonInTenant(auditor.auditDenied(
                        CatalogEntryChange.Operation.CREATE, null, CatalogEntryChangeAuditor.POLICY_DENIED)))
                .verifyComplete();
    }

    @Test
    void auditAll_emitsOneEventPerChange_resolvingTheIdentityOnce() {
        CatalogEntryChange first = CatalogEntryChange.between(entry(true, 1), entry(false, 2));
        CatalogEntryChange second = CatalogEntryChange.created(entry(true, 0));

        StepVerifier.create(asPersonInTenant(auditor.auditAll(List.of(first, second)))).verifyComplete();

        verify(auditService, times(2)).auditSuccess(anyString(), eq(PERSON), eq(ORGANIZATION), anyString(), eq(TENANT),
                any());
        verify(accessTokenService, times(1)).getOrganizationIdFromCurrentSession();
    }

    @Test
    void auditAll_withNoChanges_doesNothing() {
        StepVerifier.create(auditor.auditAll(List.of())).verifyComplete();

        verifyNoInteractions(auditService, accessTokenService);
    }

    @Test
    void audit_withoutAuthenticatedPerson_isStillRecordedAsUnknown() {
        StepVerifier.create(auditor.audit(CatalogEntryChange.created(entry(true, 0)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(auditService).auditSuccess(anyString(), eq("unknown"), any(), anyString(), eq(TENANT), any());
    }

    @Test
    void audit_withAnOrganizationThatCannotBeResolved_isStillRecorded() {
        when(accessTokenService.getOrganizationIdFromCurrentSession()).thenReturn(Mono.error(new InvalidTokenException()));

        StepVerifier.create(asPersonInTenant(auditor.audit(CatalogEntryChange.created(entry(true, 0))))).verifyComplete();

        verify(auditService).auditSuccess(anyString(), eq(PERSON), eq("unknown"), anyString(), anyString(), any());
    }

    @Test
    void audit_withoutTenantInTheContext_usesTheSystemTenant() {
        StepVerifier.create(auditor.audit(CatalogEntryChange.created(entry(true, 0)))
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(person())))
                .verifyComplete();

        verify(auditService).auditSuccess(anyString(), eq(PERSON), any(), anyString(), eq(SYSTEM_TENANT), any());
    }

    /** The change is committed already: a broken audit channel must not turn it into an error response. */
    @Test
    void audit_whenTheAuditChannelFails_doesNotFail() {
        doThrow(new IllegalStateException("audit down")).when(auditService)
                .auditSuccess(anyString(), anyString(), any(), anyString(), anyString(), any());

        StepVerifier.create(asPersonInTenant(auditor.audit(CatalogEntryChange.created(entry(true, 0)))))
                .verifyComplete();

        verify(auditService, never()).auditFailure(anyString(), any(), any(), anyString(), any());
    }

    // ---- helpers ---------------------------------------------------------------

    private static Mono<Void> asPersonInTenant(Mono<Void> mono) {
        return mono.contextWrite(ReactiveSecurityContextHolder.withAuthentication(person()))
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private static UsernamePasswordAuthenticationToken person() {
        return UsernamePasswordAuthenticationToken.authenticated(PERSON, "token", List.of());
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<Map<String, Object>> detailsCaptor() {
        return ArgumentCaptor.forClass(Map.class);
    }

    private static CatalogEntry entry(boolean enabled, long version) {
        return new CatalogEntry(DOCTORID, "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt", enabled,
                Set.of(DeliveryMode.EMAIL, DeliveryMode.UI), new CatalogEntry.Validity(36500, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("givenName")), " "), List.of(), version,
                Instant.now(), Instant.now());
    }
}
