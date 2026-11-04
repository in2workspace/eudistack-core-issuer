package es.in2.issuer.backend.issuance.application.workflow.impl;

import es.in2.issuer.backend.issuance.domain.exception.OfferNotRenewableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalDeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalInvalidIssuanceIdException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalIssuanceNotFoundException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalPermissionDeniedException;
import es.in2.issuer.backend.issuance.domain.model.CredentialOfferRenewal;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferRenewalWorkflowImplTest {

    private static final String AUTH = "Bearer token";
    private static final String BASE_URL = "https://issuer.example.com";
    private static final UUID ID = UUID.fromString("0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90");
    private static final String ORG = "VATES-B99999999";
    private static final String OFFER_URI = "openid-credential-offer://?credential_offer_uri=new";
    private static final Power ONBOARDING_EXECUTE = new Power("Execute", "DOME", "Onboarding", "Domain");
    private static final Power CERTIFICATION_ATTEST = new Power(List.of("Attest"), "DOME", "Certification", "Domain");
    private static final Power PRODUCT_OFFERING = new Power("Create", "DOME", "ProductOffering", "Domain");

    @Mock
    private AccessTokenService accessTokenService;
    @Mock
    private PolicyContextFactory policyContextFactory;
    @Mock
    private IssuanceService issuanceService;
    @Mock
    private CredentialOfferService credentialOfferService;

    @InjectMocks
    private CredentialOfferRenewalWorkflowImpl workflow;

    @BeforeEach
    void stubToken() {
        lenient().when(accessTokenService.getCleanBearerToken(AUTH)).thenReturn(Mono.just("token"));
    }

    // ── Successful renewals ───────────────────────────────────────────────────────────────

    @Test
    void renew_ui_returnsTheNewOfferUri() {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        givenIssuanceOfOrganization(draft("ui"));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectNext(new CredentialOfferRenewal(DeliveryMode.UI, OFFER_URI))
                .verifyComplete();
    }

    @Test
    void renew_email_returnsNoUri() {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        givenIssuanceOfOrganization(draft("email"));
        givenOfferDelivered("email", null, null);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectNext(new CredentialOfferRenewal(DeliveryMode.EMAIL, null))
                .verifyComplete();
    }

    /** EC-01: with email,ui stored, a single ui offer and no email. */
    @Test
    void renew_emailAndUi_deliversOnlyWithUi() {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        givenIssuanceOfOrganization(draft("email,ui"));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectNext(new CredentialOfferRenewal(DeliveryMode.UI, OFFER_URI))
                .verifyComplete();
    }

    @Test
    void renew_keepsTheGrantAndRefreshTokenOfTheIssuance() {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        Issuance issuance = draft("ui");
        issuance.setGrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        givenIssuanceOfOrganization(issuance);
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectNextCount(1)
                .verifyComplete();

        verify(credentialOfferService).createAndDeliverCredentialOffer(ID.toString(),
                "learcredential.employee.sd.1", "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "holder@example.com", "ui", "refresh-token", BASE_URL);
    }

    @Test
    void renew_withoutStoredGrant_usesAuthorizationCode() {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        Issuance issuance = draft("ui");
        issuance.setGrantType(null);
        givenIssuanceOfOrganization(issuance);
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectNextCount(1)
                .verifyComplete();

        verify(credentialOfferService).createAndDeliverCredentialOffer(anyString(), anyString(),
                eq("authorization_code"), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void renew_withCertificationAttest_isAllowed() {
        givenRequester(UserRole.LEAR, false, CERTIFICATION_ATTEST);
        givenIssuanceOfOrganization(draft("ui"));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectNextCount(1)
                .verifyComplete();
    }

    /** AC-07: a tenant administrator renews in any organization of the tenant. */
    @Test
    void renew_tenantAdmin_findsTheIssuanceInTheWholeTenant() {
        givenRequester(UserRole.TENANT_ADMIN, false, ONBOARDING_EXECUTE);
        when(issuanceService.getIssuanceById(ID.toString())).thenReturn(Mono.just(draft("ui")));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectNextCount(1)
                .verifyComplete();

        verify(issuanceService, never()).getIssuanceByIdAndOrganization(any(), anyString());
    }

    /** The platform administrator needs no power, as when issuing. */
    @Test
    void renew_sysAdminWithoutPowers_isAllowed() {
        givenRequester(UserRole.SYSADMIN, false);
        when(issuanceService.getIssuanceById(ID.toString())).thenReturn(Mono.just(draft("ui")));
        givenOfferDelivered("ui", OFFER_URI, null);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectNextCount(1)
                .verifyComplete();
    }

    // ── Order of the checks: id, permission, scope, status ────────────────────────────────

    @Test
    void renew_idNotUuid_isInvalidIdBeforeAnything() {
        StepVerifier.create(workflow.renewCredentialOffer(AUTH, "abc", BASE_URL))
                .expectError(RenewalInvalidIssuanceIdException.class)
                .verify();

        verifyNoInteractions(accessTokenService, issuanceService, credentialOfferService);
    }

    /** AC-11: who may not issue gets 403 without the issuance being looked up. */
    @Test
    void renew_withoutIssuingPower_isPermissionDeniedBeforeLookingUpTheIssuance() {
        givenRequester(UserRole.LEAR, false, PRODUCT_OFFERING);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(issuanceService, credentialOfferService);
    }

    /** ES-04: the platform's read-only view may not renew. */
    @Test
    void renew_readOnly_isPermissionDenied() {
        givenRequester(UserRole.SYSADMIN, true);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectError(RenewalPermissionDeniedException.class)
                .verify();

        verifyNoInteractions(issuanceService, credentialOfferService);
    }

    /** AC-06 / ES-02: out of scope and nonexistent are the same 404. */
    @Test
    void renew_outOfScopeOrNonexistent_isNotFound() {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        when(issuanceService.getIssuanceByIdAndOrganization(ID, ORG)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectError(RenewalIssuanceNotFoundException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** AC-03: no other status than DRAFT has an offer to renew. */
    @ParameterizedTest
    @EnumSource(value = CredentialStatusEnum.class, names = "DRAFT", mode = EnumSource.Mode.EXCLUDE)
    void renew_notDraft_isNotRenewable(CredentialStatusEnum status) {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        Issuance issuance = draft("ui");
        issuance.setCredentialStatus(status);
        givenIssuanceOfOrganization(issuance);

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectError(OfferNotRenewableException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /** AC-04. */
    @Test
    void renew_direct_isNotRenewable() {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        givenIssuanceOfOrganization(draft("direct"));

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectError(OfferNotRenewableException.class)
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    // ── Delivery failures: 503 ─────────────────────────────────────────────────────────────

    /** ES-06. */
    @Test
    void renew_emailFails_isDeliveryFailed() {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        givenIssuanceOfOrganization(draft("email"));
        givenOfferDelivered("email", null, "Error during communication with the mail server");

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectError(RenewalDeliveryFailedException.class)
                .verify();
    }

    @Test
    void renew_offerCreationFails_isDeliveryFailed() {
        givenRequester(UserRole.LEAR, false, ONBOARDING_EXECUTE);
        givenIssuanceOfOrganization(draft("ui"));
        when(credentialOfferService.createAndDeliverCredentialOffer(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalStateException("cache down")));

        StepVerifier.create(workflow.renewCredentialOffer(AUTH, ID.toString(), BASE_URL))
                .expectError(RenewalDeliveryFailedException.class)
                .verify();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private void givenRequester(UserRole role, boolean readOnly, Power... powers) {
        when(accessTokenService.getAuthorizationContext(AUTH))
                .thenReturn(Mono.just(new AuthorizationContext(ORG, role, readOnly, "multi_org")));
        when(policyContextFactory.fromTokenSimple(eq("token"), isNull()))
                .thenReturn(Mono.just(new PolicyContext(ORG, List.of(powers), null, null, null,
                        role == UserRole.SYSADMIN, role == UserRole.TENANT_ADMIN, null, null, "multi_org")));
    }

    private void givenIssuanceOfOrganization(Issuance issuance) {
        when(issuanceService.getIssuanceByIdAndOrganization(ID, ORG)).thenReturn(Mono.just(issuance));
    }

    private void givenOfferDelivered(String mode, String uri, String emailError) {
        when(credentialOfferService.createAndDeliverCredentialOffer(eq(ID.toString()), anyString(), anyString(),
                anyString(), eq(mode), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(CredentialOfferResult.builder()
                        .credentialOfferUri(uri)
                        .emailError(emailError)
                        .build()));
    }

    private static Issuance draft(String delivery) {
        return Issuance.builder()
                .issuanceId(ID)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .organizationIdentifier(ORG)
                .credentialType("learcredential.employee.sd.1")
                .email("holder@example.com")
                .delivery(delivery)
                .grantType("authorization_code")
                .credentialOfferRefreshToken("refresh-token")
                .build();
    }
}
