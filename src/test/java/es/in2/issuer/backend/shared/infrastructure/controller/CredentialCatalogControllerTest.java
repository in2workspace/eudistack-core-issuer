package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.policy.service.CatalogPdpService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.config.tenantconfig.TenantCustomDomainsLoader;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_CATALOG_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockitoBean(types = ReactiveAuthenticationManager.class)
@Import(ErrorResponseFactory.class)
@WebFluxTest(CredentialCatalogController.class)
class CredentialCatalogControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private AccessTokenService accessTokenService;

    @MockitoBean
    private CatalogPdpService catalogPdpService;

    @MockitoBean
    private TenantCredentialProfileService tenantCredentialProfileService;

    @MockitoBean
    private AuditService auditService;

    // Required only because @WebFluxTest loads all @ControllerAdvice and WebFilter beans:
    // Oidc4vciExceptionHandler depends on NonceService, IdempotencyFilter on IssuanceMetrics and
    // AccessTokenService.
    @MockitoBean
    private NonceService nonceService;

    @MockitoBean
    private IssuanceMetrics issuanceMetrics;

    @MockitoBean
    private TenantRegistryService tenantRegistryService;

    @MockitoBean
    private TenantCustomDomainsLoader tenantCustomDomainsLoader;

    @Test
    void getCatalog_asTenantAdmin_returns200WithEntries() {
        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.just(List.of(
                        new CredentialCatalogEntryDto(
                                "learcredential.employee.w3c.4",
                                "Employee",
                                true,
                                List.of(),
                                List.of()
                        )
                )));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].credentialConfigurationId")
                .isEqualTo("learcredential.employee.w3c.4")
                .jsonPath("$[0].enabled")
                .isEqualTo(true);
    }

    /**
     * AD-16 (2026-09-08 (2)): the operator (LEAR) can now read the catalog to discover a
     * type's eligible delivery modes and schema ceiling before attempting to issue it --
     * the single test in this whole Story whose intent inverts (it used to assert 403).
     */
    @Test
    void getCatalog_asLear_returns200AndReadsCatalog() {
        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.just(lear()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.just(List.of(
                        new CredentialCatalogEntryDto(
                                "learcredential.employee.w3c.4",
                                "Employee",
                                true,
                                List.of(),
                                List.of()
                        )
                )));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].credentialConfigurationId")
                .isEqualTo("learcredential.employee.w3c.4");

        verify(tenantCredentialProfileService).getCatalog();
    }

    /**
     * AC-12: the operator's read carries the same eligible-modes/schema-ceiling
     * enrichment as the administrator's, so it can guide the operator's delivery-mode
     * choice before issuance.
     */
    @Test
    void getCatalog_asLear_returns200WithDeliveryModesAndSchemaCeiling() {
        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.just(lear()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.just(List.of(
                        new CredentialCatalogEntryDto(
                                "learcredential.employee.w3c.4",
                                "Employee",
                                true,
                                List.of("email", "ui"),
                                List.of("email", "ui")
                        )
                )));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].deliveryModes[0]")
                .isEqualTo("email")
                .jsonPath("$[0].schemaEligibleModes[0]")
                .isEqualTo("email");
    }

    /**
     * EC-12: the same tenant state produces an identical payload for the administrator
     * and for the operator -- eligibility does not depend on who is asking.
     */
    @Test
    void getCatalog_sameStateAsAdminAndAsLear_returnsIdenticalPayload() {
        List<CredentialCatalogEntryDto> catalog = List.of(
                new CredentialCatalogEntryDto(
                        "learcredential.employee.w3c.4",
                        "Employee",
                        true,
                        List.of("email", "ui"),
                        List.of("email", "ui")
                )
        );

        when(tenantCredentialProfileService.getCatalog()).thenReturn(Mono.just(catalog));

        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.just(admin()));

        byte[] adminBody = webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBody();

        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.just(lear()));

        byte[] learBody = webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBody();

        assertThat(adminBody).isEqualTo(learBody);
    }

    /**
     * AD-16 / R-13: {@code UserRole} has exactly three values today, which is what makes
     * {@code canReadCredentialCatalog()}'s explicit role check vacuously true. This test
     * exists to go red the moment a fourth value is added, forcing a conscious decision
     * about whether it can read the catalog instead of it inheriting access silently.
     */
    @Test
    void canReadCredentialCatalog_allThreeRolesPass_exhaustivenessTripwire() {
        assertThat(UserRole.values()).hasSize(3);

        for (UserRole role : UserRole.values()) {
            AuthorizationContext ctx =
                    new AuthorizationContext("org-1", role, false, "tenant");

            assertThat(ctx.canReadCredentialCatalog())
                    .as("role %s must pass canReadCredentialCatalog()", role)
                    .isTrue();
        }
    }

    /**
     * A SysAdmin on the platform tenant holds a cross-tenant read-only view, so reads must
     * succeed; only writes are denied (see updateCatalog_asReadOnlyAdmin_returns403).
     */
    @Test
    void getCatalog_asReadOnlyAdmin_returns200() {
        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.just(readOnlyAdmin()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.just(List.of(
                        new CredentialCatalogEntryDto(
                                "learcredential.employee.w3c.4",
                                "Employee",
                                true,
                                List.of(),
                                List.of()
                        )
                )));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].credentialConfigurationId")
                .isEqualTo("learcredential.employee.w3c.4");
    }

    @Test
    void updateCatalog_asTenantAdmin_returns200() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        "{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}"
                )
                .exchange()
                .expectStatus().isOk();

        // Security review (EUD-169, F2): a catalog write is a policy change and must be
        // audit-logged with the caller's organization as actor -- not just a plain log line.
        verify(auditService).auditSuccess(
                eq("tenant.credential_catalog.changed"),
                eq("org-1"),
                eq("credential-catalog"),
                anyString(),
                any()
        );
    }

    @Test
    void updateCatalog_serviceFails_auditsFailureNotSuccess() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.error(
                        new UnknownCredentialConfigurationException(
                                "Unknown credential configuration id(s): [nope]"
                        )
                ));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"nope\"]}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(auditService).auditFailure(
                eq("tenant.credential_catalog.changed"),
                eq("org-1"),
                anyString(),
                any()
        );
        verify(auditService, never()).auditSuccess(
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                any()
        );
    }

    @Test
    void updateCatalog_asLear_returns403AndDoesNotWrite() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new InsufficientPermissionException("denied")));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        "{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}"
                )
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.type").isEqualTo("insufficient_permission");

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    /** AC-11, like the new API: the PDP decides before the body is read, so a malformed body is not a 400 for an operator. */
    @ParameterizedTest
    @ValueSource(strings = {"{this is not json", "{\"enabledConfigurationIds\":[]}", "{}"})
    void updateCatalog_asLear_withAnyBody_returns403InsufficientPermission(String body) {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new InsufficientPermissionException("denied")));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("insufficient_permission");

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    // ---- RFC 9745: the alias is deprecated in favour of /api/v1/attestation-catalog ----

    private static final String DEPRECATED_SINCE_2026_10_19 = "@1792368000";
    private static final String SUCCESSOR_LINK = "</api/v1/attestation-catalog>; rel=\"successor-version\"";

    @Test
    void getCatalog_carriesTheDeprecationHeaders() {
        when(catalogPdpService.authorizeRead(anyString())).thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.getCatalog()).thenReturn(Mono.just(List.of()));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Deprecation", DEPRECATED_SINCE_2026_10_19)
                .expectHeader().valueEquals("Link", SUCCESSOR_LINK);
    }

    @Test
    void updateCatalog_carriesTheDeprecationHeaders() {
        when(catalogPdpService.authorizeWrite(anyString())).thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any())).thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Deprecation", DEPRECATED_SINCE_2026_10_19)
                .expectHeader().valueEquals("Link", SUCCESSOR_LINK);
    }

    @Test
    void updateCatalog_denied_stillCarriesTheDeprecationHeaders() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new InsufficientPermissionException("denied")));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}")
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals("Deprecation", DEPRECATED_SINCE_2026_10_19)
                .expectHeader().valueEquals("Link", SUCCESSOR_LINK);
    }

    @Test
    void updateCatalog_unknownId_returns400() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.error(
                        new UnknownCredentialConfigurationException(
                                "Unknown credential configuration id(s): [nope]"
                        )
                ));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"nope\"]}")
                .exchange()
                .expectStatus().isBadRequest();
    }

    /**
     * AC-01: the catalog read carries both the eligible modes and the schema ceiling,
     * so the admin UI can disable the direct mode by reading the ceiling alone.
     */
    @Test
    void getCatalog_asTenantAdmin_includesDeliveryModesAndSchemaCeiling() {
        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.just(List.of(
                        new CredentialCatalogEntryDto(
                                "learcredential.employee.w3c.4",
                                "Employee",
                                true,
                                List.of("email", "ui"),
                                List.of("email", "ui")
                        )
                )));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].deliveryModes[0]")
                .isEqualTo("email")
                .jsonPath("$[0].deliveryModes[1]")
                .isEqualTo("ui")
                .jsonPath("$[0].schemaEligibleModes[0]")
                .isEqualTo("email")
                .jsonPath("$[0].schemaEligibleModes[1]")
                .isEqualTo("ui");
    }

    /**
     * AC-04, changed by EUD-266 (D8): a mode above the schema ceiling is a 400 {@code BAD_REQUEST} with a
     * violation, like in the attestation catalog API, no longer the 409 {@code delivery_mode_not_eligible}.
     */
    @Test
    void updateCatalog_directAboveSchemaCeiling_returns400BadRequestProblemWithAViolation() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.error(
                        new DeliveryModeNotEligibleException(
                                "Delivery mode 'direct' is not eligible for credential type "
                                        + "'learcredential.employee.w3c.4': its schema requires "
                                        + "cryptographic holder binding. Eligible modes: email,ui"
                        )
                ));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        "{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                                + "\"deliveryModesByConfigurationId\":"
                                + "{\"learcredential.employee.w3c.4\":[\"direct\"]}}"
                )
                .exchange()
                .expectStatus().isBadRequest()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.instance").isEqualTo(CREDENTIAL_CATALOG_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("deliveryModesByConfigurationId")
                .jsonPath("$.violations[0].message").value(message ->
                        assertThat(String.valueOf(message)).contains("'direct'", "learcredential.employee.w3c.4"));
    }

    /** EUD-266: the alias answers its errors as {@code application/problem+json} with the path as instance. */
    @Test
    void getCatalog_tenantWithNothingEnabled_answersAProblemJson() {
        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.error(new CredentialCatalogNotConfiguredException("No credential configuration enabled")));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("credential_catalog_not_configured")
                .jsonPath("$.instance").isEqualTo(CREDENTIAL_CATALOG_PATH);
    }

    @Test
    void updateCatalog_withBeanValidationErrors_answersAProblemJsonWithViolations() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[]}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.violations[0].field").isEqualTo("enabledConfigurationIds");
    }

    @Test
    void updateCatalog_withoutBody_answersAViolationOnTheBody() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isBadRequest()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.violations[0].field").isEqualTo("body")
                .jsonPath("$.violations[0].message").isEqualTo("is required");
    }

    /**
     * ES-01 / ES-02 / F3: invalid delivery-mode configurations are rejected with 400
     * before the service is reached.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                    + "\"deliveryModesByConfigurationId\":"
                    + "{\"learcredential.employee.w3c.4\":[\"carrier-pigeon\"]}}",
            "{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                    + "\"deliveryModesByConfigurationId\":"
                    + "{\"learcredential.employee.w3c.4\":[]}}",
            "{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                    + "\"deliveryModesByConfigurationId\":"
                    + "{\"learcredential.employee.w3c.4\":null}}"
    })
    void updateCatalog_invalidDeliveryModes_returns400WithoutCallingService(
            String requestBody
    ) {
        assertInvalidCatalogRequest(requestBody);
    }

    /**
     * ES-03: modes declared for a type outside enabledConfigurationIds (or the global
     * registry) are a 400, surfaced by the service -- unlike ES-01/02 this one needs the
     * enabled-ids subset registry / map subset enabled-ids checks the service itself owns.
     */
    @Test
    void updateCatalog_modesForNotEnabledType_returns400() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.error(
                        new InvalidDeliveryConfigException(
                                "Delivery modes declared for credential configuration id(s) "
                                        + "not enabled in this request: [other.type]"
                        )
                ));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        "{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                                + "\"deliveryModesByConfigurationId\":"
                                + "{\"other.type\":[\"email\"]}}"
                )
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void getCatalog_tenantWithNothingEnabled_returns404() {
        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.error(
                        new CredentialCatalogNotConfiguredException(
                                "No credential configuration enabled for tenant 'demo'"
                        )
                ));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isNotFound();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"enabledConfigurationIds\":[]}",
            "{}",
            "{\"enabledConfigurationIds\":[\"bad id with spaces\"]}"
    })
    void updateCatalog_invalidEnabledConfigurationIds_returns400WithoutCallingService(
            String requestBody
    ) {
        assertInvalidCatalogRequest(requestBody);
    }

    // ---- enabledConfigurationIds bounds (security review, F4) -------------------

    @Test
    void updateCatalog_tooManyEnabledConfigurationIds_returns400WithoutCallingService() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));

        String tooMany = java.util.stream.IntStream.rangeClosed(1, 65)
                .mapToObj(i -> "\"type." + i + "\"")
                .collect(java.util.stream.Collectors.joining(",", "[", "]"));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":" + tooMany + "}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    // --- Tenant-match tests (security review, EUD-169, S1) ---
    // The tenant check and its audit live in CatalogPdpService now (CatalogPdpServiceImplTest); here only
    // that a mismatch it reports reaches the client as tenant_mismatch and stops the read.

    @Test
    void getCatalog_tenantMismatch_returns403AndDoesNotRead() {
        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.error(new TenantMismatchException("Token tenant does not match")));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.type").isEqualTo("tenant_mismatch");

        verify(tenantCredentialProfileService, never()).getCatalog();
    }

    @Test
    void updateCatalog_asTenantAdmin_tenantMismatch_returns403AndDoesNotWrite() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new TenantMismatchException("Token tenant does not match")));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        "{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}"
                )
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.type").isEqualTo("tenant_mismatch");

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    @Test
    void updateCatalog_asSysAdmin_tenantMismatch_returns403AndDoesNotWrite() {
        // M2 (re-verification, reversed 2026-09-10): SysAdmin no longer bypasses
        // requireTenantMatch -- see F2 in quality-report.md.
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new TenantMismatchException("Token tenant does not match")));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(
                        "{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}"
                )
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.type").isEqualTo("tenant_mismatch");

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    // --- Authorization-denial audit tests (security review, EUD-169, F3) ---

    private void assertInvalidCatalogRequest(String requestBody) {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isBadRequest();

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    private static AuthorizationContext admin() {
        return new AuthorizationContext(
                "org-1",
                UserRole.TENANT_ADMIN,
                false,
                "tenant"
        );
    }

    private static AuthorizationContext readOnlyAdmin() {
        return new AuthorizationContext(
                "org-1",
                UserRole.SYSADMIN,
                true,
                "platform"
        );
    }

    private static AuthorizationContext lear() {
        return new AuthorizationContext(
                "org-1",
                UserRole.LEAR,
                false,
                "tenant"
        );
    }
}