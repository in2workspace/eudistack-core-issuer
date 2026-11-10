package es.in2.issuer.backend.issuance.application.workflow.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.domain.exception.OfferNotRenewableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalContentNotDecidableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalDeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalInvalidIssuanceIdException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalIssuanceNotFoundException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalPermissionDeniedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalTenantMismatchException;
import es.in2.issuer.backend.issuance.domain.model.CredentialOfferRenewal;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException.Reason;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.policy.service.impl.PowerAuthorizationServiceImpl;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.FileAuthorizationMatrixProvider;
import es.in2.issuer.backend.statuslist.domain.util.factory.IssuerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The renewal against the real decision point of EUD-272 and the bundled action matrix: who may
 * renew is who may issue the stored process again -- E1 or E6 for its type, E2 for another
 * organization, the grant rule of every power its content carries and the type enabled.
 */
class CredentialOfferRenewalWorkflowImplTest {

    private static final String TENANT = "sandbox";
    private static final String OTHER_TENANT = "kpmg";
    private static final String BASE_URL = "https://issuer.example.com";
    private static final UUID ID = UUID.fromString("0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90");
    private static final String ORG = "VATES-B99999999";
    private static final String OTHER_ORG = "VATES-A11111111";
    private static final String OFFER_URI = "openid-credential-offer://?credential_offer_uri=new";
    private static final String ATTESTATION = "urn:uuid:attestation-of-the-caller";
    private static final String LEAR_TYPE = "learcredential.employee.sd.1";
    private static final String LABEL_TYPE = "gx.labelcredential.w3c.2";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Power PLATFORM_ADMIN = power("organization", "EUDISTACK", "System", "Administration");
    private static final Power TENANT_ADMIN = power("organization", TENANT, "Onboarding", "Execute");
    private static final Power ORG_ADMIN = power("domain", TENANT, "Onboarding", "Execute");
    private static final Power CERTIFY = power("domain", TENANT, "Certification", "Attest");
    /** Read as the organization administrator power, its alias says certify: two readings (W2). */
    private static final String CONFLICTING_ALIAS_POWER = "{\"type\":\"domain\",\"domain\":\"" + TENANT
            + "\",\"function\":\"Onboarding\",\"tmf_function\":\"Certification\",\"action\":[\"Execute\"]}";
    private static final Power ORG_ADMIN_OF_ANOTHER_DOMAIN = power("domain", "DOME", "Onboarding", "Execute");

    private CallerProvider callerProvider;
    private IssuanceService issuanceService;
    private CredentialOfferService credentialOfferService;
    private AuditService auditService;
    private AuditService decisionAuditService;
    private TenantCredentialProfileService profiles;
    private CredentialOfferRenewalWorkflowImpl workflow;

    @BeforeEach
    void setUp() {
        callerProvider = mock(CallerProvider.class);
        issuanceService = mock(IssuanceService.class);
        credentialOfferService = mock(CredentialOfferService.class);
        auditService = mock(AuditService.class);
        decisionAuditService = mock(AuditService.class);
        profiles = mock(TenantCredentialProfileService.class);
        when(profiles.isProfileAllowed(anyString())).thenReturn(Mono.just(true));
        PowerAuthorizationService decisionPoint = new PowerAuthorizationServiceImpl(
                new FileAuthorizationMatrixProvider("", mock(AuditService.class)),
                callerProvider, profiles, decisionAuditService, MAPPER);
        Map<String, CredentialProfile> loaded = Map.of(LEAR_TYPE, LEAR_PROFILE, LABEL_TYPE, LABEL_PROFILE);
        CredentialProfileCatalog catalog = mock(CredentialProfileCatalog.class);
        when(catalog.getByConfigurationId(anyString()))
                .thenAnswer(invocation -> loaded.get(invocation.getArgument(0, String.class)));
        workflow = new CredentialOfferRenewalWorkflowImpl(callerProvider, decisionPoint, issuanceService, catalog,
                new GenericCredentialBuilder(MAPPER, mock(IssuerFactory.class)), credentialOfferService, auditService);
    }

    // ── Successful renewals ───────────────────────────────────────────────────────────────

    @Test
    void renew_ui_returnsTheNewOfferUri() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", ORG));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNext(new CredentialOfferRenewal(DeliveryMode.UI, OFFER_URI))
                .verifyComplete();
    }

    @Test
    void renew_email_returnsNoUri() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("email", ORG));
        givenOfferDelivered("email", null, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNext(new CredentialOfferRenewal(DeliveryMode.EMAIL, null))
                .verifyComplete();
    }

    /** EC-01: with email,ui stored, a single ui offer and no email. */
    @Test
    void renew_emailAndUi_deliversOnlyWithUi() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("email,ui", ORG));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNext(new CredentialOfferRenewal(DeliveryMode.UI, OFFER_URI))
                .verifyComplete();
    }

    @Test
    void renew_keepsTheGrantAndRefreshTokenOfTheIssuance() {
        givenCaller(ORG_ADMIN);
        Issuance issuance = draft("ui", ORG);
        issuance.setGrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        givenIssuance(issuance);
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNextCount(1)
                .verifyComplete();

        verify(credentialOfferService).createAndDeliverCredentialOffer(ID.toString(),
                "learcredential.employee.sd.1", "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "holder@example.com", "ui", "refresh-token", BASE_URL);
    }

    @Test
    void renew_withoutStoredGrant_usesAuthorizationCode() {
        givenCaller(ORG_ADMIN);
        Issuance issuance = draft("ui", ORG);
        issuance.setGrantType(null);
        givenIssuance(issuance);
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNextCount(1)
                .verifyComplete();

        verify(credentialOfferService).createAndDeliverCredentialOffer(anyString(), anyString(),
                eq("authorization_code"), anyString(), anyString(), anyString(), anyString());
    }

    /** E1: an issuance of the caller's own organization. */
    @Test
    void renew_issuanceOfTheCallersOrganization_isDecidedAsE1OnIt() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", ORG));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNextCount(1)
                .verifyComplete();

        verify(decisionAuditService).auditSuccess(eq("authorization.permit"), eq(ATTESTATION), eq("action"),
                eq(PowerAuthorizationService.ISSUE_OWN), argThat(details -> ORG.equals(details.get("resourceOrganization"))
                        && ID.toString().equals(details.get("resourceId"))));
    }

    /** AC-07: a tenant administrator renews in another organization of the tenant, decided as E2. */
    @Test
    void renew_tenantAdmin_renewsInAnotherOrganizationAsE2() {
        givenCaller(TENANT_ADMIN);
        givenIssuance(draft("ui", OTHER_ORG));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNextCount(1)
                .verifyComplete();

        verify(decisionAuditService).auditSuccess(eq("authorization.permit"), anyString(), eq("action"),
                eq("E1,E2"), argThat(details -> OTHER_ORG.equals(details.get("resourceOrganization"))));
    }

    /** Inside a tenant the platform administrator acts as its administrator, traced as a security action. */
    @Test
    void renew_platformAdmin_isDecidedAndTracedAsATenantAdmin() {
        givenCaller(PLATFORM_ADMIN);
        givenIssuance(draft("ui", OTHER_ORG));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNextCount(1)
                .verifyComplete();

        verify(decisionAuditService).auditSuccess(eq("authorization.permit"), anyString(), eq("action"),
                eq("E1,E2"), argThat(details -> "platform_admin".equals(details.get("userType"))
                        && Boolean.TRUE.equals(details.get("securityAction"))));
    }

    // ── Decided as issuing the stored process (EUD-295 review round 3, B1) ───────────────────

    /** S1: a draft carrying a power the caller may not grant is not offered again to it. */
    @Test
    void renew_draftWithAPowerTheCallerMayNotGrant_isPermissionDenied() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", ORG, LEAR_TYPE, learDataSet(TENANT_ADMIN)));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
        verify(decisionAuditService).auditFailure(eq("authorization.deny"), anyString(),
                eq(Reason.TENANT_ADMIN_DELEGATION_REQUIRES_PLATFORM_ADMIN.getCode()), any());
    }

    @Test
    void renew_draftWithAPowerTheCallerMayGrant_isRenewed() {
        givenCaller(PLATFORM_ADMIN);
        givenIssuance(draft("ui", ORG, LEAR_TYPE, learDataSet(TENANT_ADMIN)));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNext(new CredentialOfferRenewal(DeliveryMode.UI, OFFER_URI))
                .verifyComplete();
    }

    /** Decision 1 of the round-2 review: a product certification is renewed with E6. */
    @Test
    void renew_productCertificationWithOnlyCertificationAttest_isRenewed() {
        givenCaller(CERTIFY);
        givenIssuance(draft("ui", ORG, LABEL_TYPE, labelDataSet()));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNext(new CredentialOfferRenewal(DeliveryMode.UI, OFFER_URI))
                .verifyComplete();
    }

    @Test
    void renew_productCertificationWithoutCertificationAttest_isPermissionDenied() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", ORG, LABEL_TYPE, labelDataSet()));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** W2: a draft from before EUD-272 whose power names a field and its alias differently could not be issued today. */
    @Test
    void renew_draftWithAPowerWhoseFieldAndAliasDiffer_isPermissionDenied() {
        givenCaller(TENANT_ADMIN);
        givenIssuance(draft("ui", ORG, LEAR_TYPE, learDataSetWithRawPower(CONFLICTING_ALIAS_POWER)));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
        verify(decisionAuditService).auditFailure(eq("authorization.deny"), anyString(),
                eq("power_alias_conflict"), any());
    }

    /** W2 keeps AC-06: the same draft of another organization is still not found to who may not issue there. */
    @Test
    void renew_draftOfAnotherOrganizationWithAPowerWhoseFieldAndAliasDiffer_isNotFound() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", OTHER_ORG, LEAR_TYPE, learDataSetWithRawPower(CONFLICTING_ALIAS_POWER)));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verify(decisionAuditService, never()).auditFailure(eq("authorization.deny"), anyString(),
                eq("power_alias_conflict"), any());
    }

    /** FR-07: a type no longer enabled in the tenant is not offered again. */
    @Test
    void renew_typeNoLongerEnabled_isPermissionDenied() {
        when(profiles.isProfileAllowed(LEAR_TYPE)).thenReturn(Mono.just(false));
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** Fail closed: content that cannot be read cannot be decided, and the denial is audited here. */
    @Test
    void renew_unreadableContent_isPermissionDeniedAndAudited() {
        givenCaller(TENANT_ADMIN);
        givenIssuance(draft("ui", ORG, LEAR_TYPE, "not json"));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalContentNotDecidableException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
        verify(auditService).auditFailure(eq(CredentialOfferRenewalWorkflowImpl.EVENT_FAILED), eq(ATTESTATION),
                eq("content_not_decidable"), any());
    }

    @Test
    void renew_typeWithoutProfile_isPermissionDenied() {
        givenCaller(TENANT_ADMIN);
        givenIssuance(draft("ui", ORG, "unknown.type.1", learDataSet()));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalContentNotDecidableException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** Who may only certify products may issue: a nonexistent id is not found for it, not forbidden. */
    @Test
    void renew_nonexistentWithOnlyCertificationAttest_isNotFound() {
        givenCaller(CERTIFY);
        when(issuanceService.getIssuanceById(ID.toString())).thenReturn(Mono.empty());

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();
    }

    // ── Who may not renew (EUD-295 review, S1) ────────────────────────────────────────────

    /** AC-11: a user of the issuance's organization without the power to issue gets 403. */
    @Test
    void renew_userWithoutPowers_isPermissionDenied() {
        givenCaller();
        givenIssuance(draft("ui", ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** Certification · Attest is E6 (product certifications), not E1: it does not let renew a LEAR draft. */
    @Test
    void renew_onlyCertificationAttest_isPermissionDenied() {
        givenCaller(CERTIFY);
        givenIssuance(draft("ui", ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** A power never leaves its domain: Onboarding · Execute of another domain is no power in this tenant. */
    @Test
    void renew_onboardingOfAnotherDomain_isPermissionDenied() {
        givenCaller(ORG_ADMIN_OF_ANOTHER_DOMAIN);
        givenIssuance(draft("ui", ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** AC-11: the same 403 for a UUID that does not exist and for another organization's issuance. */
    @Test
    void renew_userWithoutPowers_isPermissionDeniedAlsoForANonexistentId() {
        givenCaller();
        when(issuanceService.getIssuanceById(ID.toString())).thenReturn(Mono.empty());

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();
    }

    @Test
    void renew_userWithoutPowers_isPermissionDeniedAlsoForAnotherOrganization() {
        givenCaller();
        givenIssuance(draft("ui", OTHER_ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** ES-04: from the platform tenant the platform administrator only reads. */
    @Test
    void renew_platformAdminFromThePlatformTenant_isPermissionDenied() {
        givenCallerOfTenant("platform", PLATFORM_ADMIN);
        givenIssuance(draft("ui", ORG));

        StepVerifier.create(renew(ID.toString(), "platform"))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
        // Decided without the stored type, E1 and then E6, each denied with its reason (N2 of the review).
        verify(decisionAuditService, times(2)).auditFailure(eq("authorization.deny"), anyString(),
                eq("platform_tenant_read_only"), any());
    }

    // ── Scope: out of scope reads as not found ────────────────────────────────────────────

    /** AC-06: an organization administrator finds another organization's issuance as not found. */
    @Test
    void renew_organizationAdminOnAnotherOrganization_isNotFound() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", OTHER_ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
        verify(decisionAuditService).auditFailure(eq("authorization.deny"), anyString(),
                eq(Reason.ON_BEHALF_REQUIRES_TENANT_ADMIN.getCode()), any());
    }

    /**
     * N1 of the review, round 4: out of scope reads as not found whatever the process stores. Who may
     * issue but not in another organization learns neither that the id exists nor the class of its type.
     */
    @Test
    void renew_organizationAdminOnAProductCertificationOfAnotherOrganization_isNotFound() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", OTHER_ORG, LABEL_TYPE, labelDataSet()));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void renew_certifierOnALearDraftOfAnotherOrganization_isNotFound() {
        givenCaller(CERTIFY);
        givenIssuance(draft("ui", OTHER_ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void renew_organizationAdminOnUnreadableContentOfAnotherOrganization_isNotFoundAndNotAuditedAsUndecidable() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", OTHER_ORG, LEAR_TYPE, "not json"));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verify(auditService, never()).auditFailure(eq(CredentialOfferRenewalWorkflowImpl.EVENT_FAILED), anyString(),
                eq("content_not_decidable"), any());
    }

    @Test
    void renew_organizationAdminOnADraftOfAnotherOrganizationWithAPowerItMayNotGrant_isNotFound() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", OTHER_ORG, LEAR_TYPE, learDataSet(TENANT_ADMIN)));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();
    }

    /** In scope, the stored content is decided: a tenant administrator on unreadable content gets 403. */
    @Test
    void renew_tenantAdminOnUnreadableContentOfAnotherOrganization_isContentNotDecidable() {
        givenCaller(TENANT_ADMIN);
        givenIssuance(draft("ui", OTHER_ORG, LEAR_TYPE, "not json"));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalContentNotDecidableException.class)
                .verify();
    }

    /** An issuance stored without an organization (before EUD-272) belongs to none. */
    @Test
    void renew_organizationAdminOnAnIssuanceWithoutOrganization_isNotFound() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", null));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();
    }

    /** ES-02: a UUID that is not in the tenant, decided without a resource and then not found. */
    @Test
    void renew_nonexistent_isNotFoundAndTracedAsNotFound() {
        givenCaller(ORG_ADMIN);
        when(issuanceService.getIssuanceById(ID.toString())).thenReturn(Mono.empty());

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verify(decisionAuditService).auditSuccess(eq("authorization.permit"), anyString(), eq("action"),
                eq(PowerAuthorizationService.ISSUE_OWN), argThat(details -> Boolean.FALSE.equals(details.get("resourceFound"))));
        verifyNoInteractions(credentialOfferService);
    }

    // ── Order of the checks: tenant, id, permission, scope, status ────────────────────────

    /** ES-05: a token for another tenant is rejected first, even with a malformed id. */
    @Test
    void renew_tokenOfAnotherTenant_isTenantMismatchBeforeTheId() {
        givenCallerOfTenant(OTHER_TENANT, TENANT_ADMIN);

        StepVerifier.create(renew("abc"))
                .expectError(RenewalTenantMismatchException.class)
                .verify();

        verifyNoInteractions(issuanceService, credentialOfferService);
        verify(decisionAuditService).auditFailure(eq("authorization.deny"), anyString(), eq("tenant_mismatch"), any());
    }

    @Test
    void renew_tokenWithoutTenant_isTenantMismatch() {
        givenCallerOfTenant(null, ORG_ADMIN);

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalTenantMismatchException.class)
                .verify();

        verifyNoInteractions(issuanceService);
    }

    /** ES-01, before the permission: who may not issue still gets 400 for a malformed id. */
    @Test
    void renew_idNotUuid_isInvalidIdBeforeThePermission() {
        givenCaller();

        StepVerifier.create(renew("abc"))
                .expectError(RenewalInvalidIssuanceIdException.class)
                .verify();

        verifyNoInteractions(issuanceService, credentialOfferService);
    }

    /** A shortened form that UUID.fromString accepts is not an issuance id either (EUD-307). */
    @Test
    void renew_nonCanonicalUuid_isInvalidId() {
        givenCaller(ORG_ADMIN);

        StepVerifier.create(renew("1-1-1-1-1"))
                .expectError(RenewalInvalidIssuanceIdException.class)
                .verify();

        verifyNoInteractions(issuanceService);
    }

    /** AC-03: no other status than DRAFT has an offer to renew. */
    @ParameterizedTest
    @EnumSource(value = CredentialStatusEnum.class, names = "DRAFT", mode = EnumSource.Mode.EXCLUDE)
    void renew_notDraft_isNotRenewable(CredentialStatusEnum status) {
        givenCaller(ORG_ADMIN);
        Issuance issuance = draft("ui", ORG);
        issuance.setCredentialStatus(status);
        givenIssuance(issuance);

        StepVerifier.create(renew(ID.toString()))
                .expectError(OfferNotRenewableException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** AC-04. */
    @Test
    void renew_direct_isNotRenewable() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("direct", ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(OfferNotRenewableException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /**
     * W2 of the review, round 5: status and mode (409) are decided after existence, scope and content
     * (step 5 of "Orden de las comprobaciones"). Out of scope, a process that is no longer a draft or
     * has no offer reads as not found, so the 409 says nothing of another organization's processes.
     */
    @ParameterizedTest
    @EnumSource(value = CredentialStatusEnum.class, names = "DRAFT", mode = EnumSource.Mode.EXCLUDE)
    void renew_notDraftOfAnotherOrganization_isNotFoundBeforeNotRenewable(CredentialStatusEnum status) {
        givenCaller(ORG_ADMIN);
        Issuance issuance = draft("ui", OTHER_ORG);
        issuance.setCredentialStatus(status);
        givenIssuance(issuance);

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void renew_directOfAnotherOrganization_isNotFoundBeforeNotRenewable() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("direct", OTHER_ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** In scope, the content is decided before the status: unreadable content is 403, not 409. */
    @Test
    void renew_notDraftWithUnreadableContent_isContentNotDecidableBeforeNotRenewable() {
        givenCaller(TENANT_ADMIN);
        Issuance issuance = draft("ui", ORG, LEAR_TYPE, "not json");
        issuance.setCredentialStatus(CredentialStatusEnum.VALID);
        givenIssuance(issuance);

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalContentNotDecidableException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** Who may not issue is denied (403) before the status is looked at. */
    @Test
    void renew_userWithoutPowersOnANotDraft_isPermissionDeniedBeforeNotRenewable() {
        givenCaller();
        Issuance issuance = draft("ui", ORG);
        issuance.setCredentialStatus(CredentialStatusEnum.VALID);
        givenIssuance(issuance);

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();
    }

    // ── Delivery failures: 503 ─────────────────────────────────────────────────────────────

    /** ES-06. */
    @Test
    void renew_emailFails_isDeliveryFailed() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("email", ORG));
        givenOfferDelivered("email", null, "Error during communication with the mail server");

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalDeliveryFailedException.class)
                .verify();
    }

    @Test
    void renew_offerCreationFails_isDeliveryFailed() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", ORG));
        when(credentialOfferService.createAndDeliverCredentialOffer(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalStateException("cache down")));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalDeliveryFailedException.class)
                .verify();
    }

    // ── Audit of the outcome (conv-quality-security-gates §3.4) ───────────────────────────

    /** W2: the actor is the caller's attestation, as the decision point traces it, never an email. */
    @Test
    void renew_success_auditsTheRenewalWithTheCallersAttestation() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", ORG));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNextCount(1)
                .verifyComplete();

        verify(auditService).auditSuccess(eq(CredentialOfferRenewalWorkflowImpl.EVENT_RENEWED), eq(ATTESTATION),
                eq("issuance"), eq(ID.toString()), argThat(details -> "ui".equals(details.get("mode"))
                        && ORG.equals(details.get("callerOrganization"))
                        && ID.toString().equals(details.get("resourceId"))));
        verify(auditService, never()).auditFailure(anyString(), any(), anyString(), any());
    }

    @Test
    void renew_withoutAttestationId_auditsTheTokenId() {
        when(callerProvider.current()).thenReturn(Mono.just(
                new Caller(ORG, List.of(ORG_ADMIN), TENANT, "learcredential.employee.w3c.4", "jti-1")));
        givenIssuance(draft("ui", ORG));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(renew(ID.toString()))
                .expectNextCount(1)
                .verifyComplete();

        verify(auditService).auditSuccess(eq(CredentialOfferRenewalWorkflowImpl.EVENT_RENEWED), eq("jti-1"),
                anyString(), anyString(), any());
    }

    /**
     * W1 of the review, round 5: E1 and E6 are decided without a resource, so the decision point does
     * not trace which issuance was denied. The renewal audits the denial with the id of the issuance.
     */
    @Test
    void renew_deniedOnAnExistingIssuance_isAuditedWithItsId() {
        givenCaller();
        givenIssuance(draft("ui", ORG));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        // E1 and then E6, decided without the stored type: one deny each (N2 of the review).
        verify(decisionAuditService, times(2)).auditFailure(eq("authorization.deny"), eq(ATTESTATION), anyString(), any());
        verify(auditService).auditFailure(eq(CredentialOfferRenewalWorkflowImpl.EVENT_FAILED), eq(ATTESTATION),
                eq("permission_denied"), argThat((Map<String, Object> details) ->
                        ID.toString().equals(details.get("resourceId"))
                                && ORG.equals(details.get("callerOrganization"))));
    }

    /** Content that cannot be decided keeps its own reason: it is not audited again as a plain denial. */
    @Test
    void renew_unreadableContent_isNotAuditedAsPermissionDenied() {
        givenCaller(TENANT_ADMIN);
        givenIssuance(draft("ui", ORG, LEAR_TYPE, "not json"));

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalContentNotDecidableException.class)
                .verify();

        verify(auditService, never()).auditFailure(anyString(), anyString(), eq("permission_denied"), any());
    }

    /** A token of another tenant is traced by the decision point before the id is read: no outcome here. */
    @Test
    void renew_tokenOfAnotherTenant_isNotAuditedByTheRenewal() {
        givenCallerOfTenant(OTHER_TENANT, TENANT_ADMIN);

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalTenantMismatchException.class)
                .verify();

        verifyNoInteractions(auditService);
    }

    @Test
    void renew_notFound_auditsTheFailedOutcome() {
        givenCaller(ORG_ADMIN);
        when(issuanceService.getIssuanceById(ID.toString())).thenReturn(Mono.empty());

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verify(auditService).auditFailure(eq(CredentialOfferRenewalWorkflowImpl.EVENT_FAILED), eq(ATTESTATION),
                eq("issuance_not_found"), any());
    }

    /** N5: a malformed id is audited as such, never as the string the client sent. */
    @Test
    void renew_malformedId_auditsItAsMalformed() {
        givenCaller(ORG_ADMIN);

        StepVerifier.create(renew("<script>"))
                .expectError(RenewalInvalidIssuanceIdException.class)
                .verify();

        verify(auditService).auditFailure(eq(CredentialOfferRenewalWorkflowImpl.EVENT_FAILED), anyString(),
                eq("invalid_issuance_id"), argThat((Map<String, Object> details) ->
                        CredentialOfferRenewalWorkflowImpl.MALFORMED_ID.equals(details.get("resourceId"))));
    }

    @Test
    void renew_deliveryFails_auditsTheFailedOutcome() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("email", ORG));
        givenOfferDelivered("email", null, "smtp down");

        StepVerifier.create(renew(ID.toString()))
                .expectError(RenewalDeliveryFailedException.class)
                .verify();

        verify(auditService).auditFailure(eq(CredentialOfferRenewalWorkflowImpl.EVENT_FAILED), anyString(),
                eq("delivery_failed"), any());
    }

    /** N4: a renewal the client cancels leaves an outcome event. */
    @Test
    void renew_cancelled_auditsTheCancellation() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", ORG));
        PublisherProbe<CredentialOfferResult> delivery = PublisherProbe.of(Mono.never());
        when(credentialOfferService.createAndDeliverCredentialOffer(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString())).thenReturn(delivery.mono());

        StepVerifier.create(renew(ID.toString()))
                .thenAwait()
                .thenCancel()
                .verify();

        verify(auditService).auditFailure(eq(CredentialOfferRenewalWorkflowImpl.EVENT_CANCELLED), eq(ATTESTATION),
                eq("cancelled"), any());
        delivery.assertWasCancelled();
    }

    @Test
    void renew_auditChannelFails_theRenewalStillSucceeds() {
        givenCaller(ORG_ADMIN);
        givenIssuance(draft("ui", ORG));
        givenOfferDelivered("ui", OFFER_URI, null);
        doThrow(new IllegalStateException("audit down"))
                .when(auditService).auditSuccess(anyString(), any(), anyString(), any(), any());

        StepVerifier.create(renew(ID.toString()))
                .expectNext(new CredentialOfferRenewal(DeliveryMode.UI, OFFER_URI))
                .verifyComplete();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private Mono<CredentialOfferRenewal> renew(String issuanceId) {
        return renew(issuanceId, TENANT);
    }

    /** As TenantDomainWebFilter does: the request's tenant travels in the Reactor context. */
    private Mono<CredentialOfferRenewal> renew(String issuanceId, String requestTenant) {
        return workflow.renewCredentialOffer(issuanceId, BASE_URL)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, requestTenant));
    }

    private static Power power(String type, String domain, String function, String action) {
        return new Power(List.of(action), domain, function, type);
    }

    private void givenCaller(Power... powers) {
        givenCallerOfTenant(TENANT, powers);
    }

    /** A caller of {@link #ORG} whose token was issued for {@code tokenTenant}. */
    private void givenCallerOfTenant(String tokenTenant, Power... powers) {
        when(callerProvider.current()).thenReturn(Mono.just(new Caller(ORG, List.of(powers), tokenTenant,
                "learcredential.employee.w3c.4", "jti-1", ATTESTATION)));
    }

    private void givenIssuance(Issuance issuance) {
        when(issuanceService.getIssuanceById(ID.toString())).thenReturn(Mono.just(issuance));
    }

    private void givenOfferDelivered(String mode, String uri, String emailError) {
        when(credentialOfferService.createAndDeliverCredentialOffer(eq(ID.toString()), anyString(), anyString(),
                anyString(), eq(mode), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(CredentialOfferResult.builder()
                        .credentialOfferUri(uri)
                        .emailError(emailError)
                        .build()));
    }

    private static Issuance draft(String delivery, String organization) {
        return draft(delivery, organization, LEAR_TYPE, learDataSet());
    }

    private static Issuance draft(String delivery, String organization, String type, String dataSet) {
        return Issuance.builder()
                .issuanceId(ID)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .organizationIdentifier(organization)
                .credentialType(type)
                .credentialDataSet(dataSet)
                .email("holder@example.com")
                .delivery(delivery)
                .grantType("authorization_code")
                .credentialOfferRefreshToken("refresh-token")
                .build();
    }

    private static final CredentialProfile LEAR_PROFILE = CredentialProfile.builder()
            .credentialConfigurationId(LEAR_TYPE)
            .format("dc+sd-jwt")
            .sdJwt(CredentialProfile.SdJwtConfig.builder().vct("urn:test:employee").build())
            .credentialSubjectStrategy("mandate")
            .build();

    private static final CredentialProfile LABEL_PROFILE = CredentialProfile.builder()
            .credentialConfigurationId(LABEL_TYPE)
            .format("jwt_vc_json")
            .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                    .type(List.of("gx:LabelCredential", "VerifiableCredential"))
                    .build())
            .credentialSubjectStrategy("direct")
            .build();

    /** A flat SD-JWT LEAR as the builder stores it: the payload under {@code mandate}. */
    private static String learDataSet(Power... granted) {
        var credential = MAPPER.createObjectNode().put("vct", "urn:test:employee");
        var mandate = credential.putObject("mandate");
        mandate.putObject("mandator").put("organizationIdentifier", ORG);
        mandate.putObject("mandatee").put("firstName", "Ana");
        var powers = mandate.putArray("power");
        for (Power power : granted) {
            powers.add(MAPPER.valueToTree(power));
        }
        return credential.toString();
    }

    private static String learDataSetWithRawPower(String rawPower) {
        var credential = MAPPER.createObjectNode().put("vct", "urn:test:employee");
        var mandate = credential.putObject("mandate");
        mandate.putObject("mandator").put("organizationIdentifier", ORG);
        mandate.putObject("mandatee").put("firstName", "Ana");
        try {
            mandate.putArray("power").add(MAPPER.readTree(rawPower));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
        return credential.toString();
    }

    /** A W3C product certification as the builder stores it: the payload as {@code credentialSubject}. */
    private static String labelDataSet() {
        var credential = MAPPER.createObjectNode();
        credential.putArray("type").add("gx:LabelCredential").add("VerifiableCredential");
        credential.putObject("credentialSubject").put("id", "urn:uuid:product-1");
        return credential.toString();
    }
}
