package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException.Violation;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.exception.PreconditionFailedException;
import es.in2.issuer.backend.shared.domain.exception.PreconditionRequiredException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.exception.UnknownSchemaException;
import es.in2.issuer.backend.shared.domain.exception.UnsupportedBindingTypeException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryChange;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.catalog.CreateCatalogEntryCommand;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.policy.service.CatalogPdpService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AttestationCatalogService;
import es.in2.issuer.backend.shared.domain.service.CatalogEntryChangeAuditor;
import es.in2.issuer.backend.shared.domain.service.CatalogEntryValidator;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ATTESTATION_CATALOG_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

/**
 * Every response of the Attestation Catalogue contract through the controller and its problem+json
 * advice. {@code @WebFluxTest} has no {@code base-path}: {@code Location} and {@code instance} carry no
 * {@code /issuer} here, the IT checks the prefix.
 */
@WithMockUser
@MockitoBean(types = ReactiveAuthenticationManager.class)
@Import({ErrorResponseFactory.class, CatalogExceptionHandler.class})
@WebFluxTest(AttestationCatalogController.class)
class AttestationCatalogControllerTest {

    private static final String ID = "doctorid.sd.1";
    private static final String ENTRY_PATH = ATTESTATION_CATALOG_PATH + "/" + ID;
    private static final String DOCTORID_URI = "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt";
    private static final String BEARER = "Bearer token";

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private CatalogPdpService catalogPdpService;

    @MockitoBean
    private AttestationCatalogService service;

    @MockitoBean
    private CatalogEntryChangeAuditor changeAuditor;

    // Required only because @WebFluxTest loads every @ControllerAdvice and WebFilter bean:
    // Oidc4vciExceptionHandler needs NonceService, IdempotencyFilter needs IssuanceMetrics and AccessTokenService.
    @MockitoBean
    private NonceService nonceService;

    @MockitoBean
    private AccessTokenService accessTokenService;

    @MockitoBean
    private IssuanceMetrics issuanceMetrics;

    @MockitoBean
    private TenantRegistryService tenantRegistryService;

    @BeforeEach
    void allowEverything() {
        AuthorizationContext administrator = new AuthorizationContext("org-1", UserRole.TENANT_ADMIN, false, "tenant");
        when(catalogPdpService.authorizeRead(anyString())).thenReturn(Mono.just(administrator));
        when(catalogPdpService.authorizeWrite(anyString())).thenReturn(Mono.just(administrator));
        when(changeAuditor.auditDenied(any(), any(), any())).thenReturn(Mono.empty());
    }

    // ---- GET / ------------------------------------------------------------------

    @Test
    void list_returnsTheEntriesInTheContractShape() {
        when(service.list(null)).thenReturn(Flux.just(doctorId(3)));

        webTestClient.get().uri(ATTESTATION_CATALOG_PATH)
                .header("Authorization", BEARER)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$[0].credential_configuration_id").isEqualTo(ID)
                .jsonPath("$[0].schema_uri").isEqualTo(DOCTORID_URI)
                .jsonPath("$[0].enabled").isEqualTo(true)
                .jsonPath("$[0].delivery_modes[0]").isEqualTo("email")
                .jsonPath("$[0].delivery_modes[1]").isEqualTo("ui")
                .jsonPath("$[0].validity.default_days").isEqualTo(36500)
                .jsonPath("$[0].validity.requester_can_set_dates").isEqualTo(false)
                .jsonPath("$[0].subject.fields[0][0]").isEqualTo("givenName")
                .jsonPath("$[0].subject.fields[1][0]").isEqualTo("familyName")
                .jsonPath("$[0].subject.separator").isEqualTo(" ")
                .jsonPath("$[0].search_identifiers[0].name").isEqualTo("colegiado")
                .jsonPath("$[0].search_identifiers[0].field[0]").isEqualTo("personal_administrative_number")
                .jsonPath("$[0].created").isEqualTo("2026-10-19T08:00:00Z")
                .jsonPath("$[0].updated").isEqualTo("2026-10-19T09:30:00Z");
    }

    @Test
    void list_withoutEntries_returnsAnEmptyArray() {
        when(service.list(null)).thenReturn(Flux.empty());

        webTestClient.get().uri(ATTESTATION_CATALOG_PATH)
                .header("Authorization", BEARER)
                .exchange()
                .expectStatus().isOk()
                .expectBody().json("[]", true);
    }

    @Test
    void list_withTheEnabledFilter_passesItToTheService() {
        when(service.list(false)).thenReturn(Flux.empty());

        webTestClient.get().uri(ATTESTATION_CATALOG_PATH + "?enabled=false")
                .header("Authorization", BEARER)
                .exchange()
                .expectStatus().isOk();

        verify(service).list(false);
    }

    @Test
    void list_withAnEnabledFilterThatIsNotABoolean_isBadRequestProblem() {
        webTestClient.get().uri(ATTESTATION_CATALOG_PATH + "?enabled=maybe")
                .header("Authorization", BEARER)
                .exchange()
                .expectStatus().isBadRequest()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.instance").isEqualTo(ATTESTATION_CATALOG_PATH)
                .jsonPath("$.violations").doesNotExist();
    }

    /** A row whose type file is gone and that was never completed has nothing the contract could show. */
    @Test
    void list_leavesOutARowThatIsNotFilled() {
        CatalogEntry unfilled = new CatalogEntry("removed.type.1", null, true, null, null, null, List.of(), 0,
                Instant.parse("2026-10-19T08:00:00Z"), Instant.parse("2026-10-19T08:00:00Z"));
        when(service.list(null)).thenReturn(Flux.just(unfilled, doctorId(1)));

        webTestClient.get().uri(ATTESTATION_CATALOG_PATH)
                .header("Authorization", BEARER)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.length()").isEqualTo(1)
                .jsonPath("$[0].credential_configuration_id").isEqualTo(ID);
    }

    @Test
    void list_asOperator_readsWithTheReadAuthorization() {
        when(service.list(null)).thenReturn(Flux.empty());

        webTestClient.get().uri(ATTESTATION_CATALOG_PATH)
                .header("Authorization", BEARER)
                .exchange()
                .expectStatus().isOk();

        verify(catalogPdpService).authorizeRead(BEARER);
        verify(catalogPdpService, never()).authorizeWrite(anyString());
    }

    // ---- GET /{id} ---------------------------------------------------------------

    @Test
    void get_returnsTheEntryWithItsStrongETag() {
        when(service.get(ID)).thenReturn(Mono.just(doctorId(7)));

        webTestClient.get().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("ETag", "\"7\"")
                .expectBody()
                .jsonPath("$.credential_configuration_id").isEqualTo(ID);
    }

    @Test
    void get_entryWithoutSubjectNorMaxDays_doesNotSerializeNulls() {
        CatalogEntry withoutSubject = new CatalogEntry(ID, DOCTORID_URI, false, Set.of(DeliveryMode.DIRECT),
                new CatalogEntry.Validity(30, false, null), null, List.of(), 1,
                Instant.parse("2026-10-19T08:00:00Z"), Instant.parse("2026-10-19T08:00:00Z"));
        when(service.get(ID)).thenReturn(Mono.just(withoutSubject));

        webTestClient.get().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .doesNotContain("null")
                        .doesNotContain("\"subject\"")
                        .doesNotContain("max_days")
                        .contains("\"delivery_modes\":[\"direct\"]")
                        .contains("\"search_identifiers\":[]"));
    }

    @Test
    void get_aRowThatIsNotFilled_isNotFound() {
        CatalogEntry unfilled = new CatalogEntry("removed.type.1", null, true, null, null, null, List.of(), 0, null, null);
        when(service.get("removed.type.1")).thenReturn(Mono.just(unfilled));

        webTestClient.get().uri(ATTESTATION_CATALOG_PATH + "/removed.type.1")
                .header("Authorization", BEARER)
                .exchange()
                .expectStatus().isNotFound()
                .expectBody().jsonPath("$.type").isEqualTo("catalog_entry_not_found");
    }

    // ---- POST --------------------------------------------------------------------

    @Test
    void create_returns201WithLocationAndETag() {
        when(service.create(any())).thenReturn(Mono.just(doctorId(0)));

        webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                .header("Authorization", BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(DOCTORID_CREATE_BODY)
                .exchange()
                .expectStatus().isCreated()
                .expectHeader().valueEquals("Location", ENTRY_PATH)
                .expectHeader().valueEquals("ETag", "\"0\"")
                .expectBody()
                .jsonPath("$.credential_configuration_id").isEqualTo(ID);

        ArgumentCaptor<CreateCatalogEntryCommand> command = ArgumentCaptor.forClass(CreateCatalogEntryCommand.class);
        verify(service).create(command.capture());
        assertThat(command.getValue().schemaUri()).isEqualTo(DOCTORID_URI);
        CatalogConfigurationInput configuration = command.getValue().configuration();
        assertThat(configuration.enabled()).isTrue();
        assertThat(configuration.deliveryModes()).containsExactly("email", "ui");
        assertThat(configuration.validity().defaultDays()).isEqualTo(36500);
        assertThat(configuration.validity().requesterCanSetDates()).isFalse();
        assertThat(configuration.subject().fields()).containsExactly(List.of("givenName"), List.of("familyName"));
        assertThat(configuration.subject().separator()).isEqualTo(" ");
        assertThat(configuration.searchIdentifiers().getFirst().field()).containsExactly("personal_administrative_number");
        assertThat(configuration.unknownFields()).isEmpty();
    }

    @Test
    void create_subjectWithoutSeparator_reachesTheServiceWithoutOneToLetItDefault() {
        when(service.create(any())).thenReturn(Mono.just(doctorId(0)));

        webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                .header("Authorization", BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(createBodyWith(ENABLED, MODES, VALIDITY, "\"subject\": {\"fields\": [[\"givenName\"]]}"))
                .exchange()
                .expectStatus().isCreated();

        ArgumentCaptor<CreateCatalogEntryCommand> command = ArgumentCaptor.forClass(CreateCatalogEntryCommand.class);
        verify(service).create(command.capture());
        assertThat(command.getValue().configuration().subject().separator()).isNull();
    }

    // ---- PUT /{id} ---------------------------------------------------------------

    @Test
    void replace_withTheWholeEntryThatGetReturned_returns200AndIgnoresWhatIsNotConfiguration() {
        when(service.replace(eq(ID), any(), eq("\"3\""))).thenReturn(Mono.just(doctorId(4)));
        String wholeEntryFromGet = """
                {"credential_configuration_id": "%s", "schema_uri": "%s", "created": "2026-10-19T08:00:00Z",
                 "updated": "2026-10-19T09:30:00Z", %s}""".formatted(ID, DOCTORID_URI, CONFIGURATION);

        webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", "\"3\"")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(wholeEntryFromGet)
                .exchange()
                .expectStatus().isOk();

        ArgumentCaptor<CatalogConfigurationInput> input = ArgumentCaptor.forClass(CatalogConfigurationInput.class);
        verify(service).replace(eq(ID), input.capture(), eq("\"3\""));
        assertThat(input.getValue().unknownFields()).isEmpty();
    }

    @Test
    void replace_returnsTheNewETag_andItIsTheIfMatchOfTheNextChangeWithoutAGet() {
        when(service.replace(eq(ID), any(), eq("\"3\""))).thenReturn(Mono.just(doctorId(4)));
        when(service.setEnabled(ID, false, "\"4\"")).thenReturn(Mono.just(doctorId(5)));

        String newETag = webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", "\"3\"")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{" + CONFIGURATION + "}")
                .exchange()
                .expectStatus().isOk()
                .returnResult(String.class)
                .getResponseHeaders().getETag();
        assertThat(newETag).isEqualTo("\"4\"");

        webTestClient.mutateWith(csrf()).patch().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", newETag)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\": false}")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("ETag", "\"5\"");
    }

    @Test
    void replace_withoutIfMatch_leavesTheDecisionToTheServiceAnd428IsNotA400() {
        when(service.replace(eq(ID), any(), isNull()))
                .thenReturn(Mono.error(new PreconditionRequiredException("The If-Match header is required")));

        assertProblem(webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{" + CONFIGURATION + "}")
                        .exchange(),
                428, "precondition_required", ENTRY_PATH);
    }

    // ---- PATCH /{id} -------------------------------------------------------------

    @Test
    void patch_returns200WithTheNewETag() {
        when(service.setEnabled(ID, true, "\"1\"")).thenReturn(Mono.just(doctorId(2)));

        webTestClient.mutateWith(csrf()).patch().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", "\"1\"")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\": true}")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("ETag", "\"2\"");
    }

    @Test
    void patch_withoutIfMatch_isPreconditionRequired() {
        when(service.setEnabled(ID, true, null))
                .thenReturn(Mono.error(new PreconditionRequiredException("The If-Match header is required")));

        assertProblem(webTestClient.mutateWith(csrf()).patch().uri(ENTRY_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{\"enabled\": true}")
                        .exchange(),
                428, "precondition_required", ENTRY_PATH);
    }

    @Test
    void patch_withAnUnknownField_isBadRequestWithAViolationPerField() {
        WebTestClient.ResponseSpec response = webTestClient.mutateWith(csrf()).patch().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", "\"1\"")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\": true, \"delivery_modes\": [\"email\"]}")
                .exchange();

        assertProblem(response, 400, "BAD_REQUEST", ENTRY_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("delivery_modes");
        verify(service, never()).setEnabled(anyString(), org.mockito.ArgumentMatchers.anyBoolean(), any());
    }

    @Test
    void patch_withoutEnabled_isBadRequestWithAViolation() {
        WebTestClient.ResponseSpec response = webTestClient.mutateWith(csrf()).patch().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", "\"1\"")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange();

        assertProblem(response, 400, "BAD_REQUEST", ENTRY_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("enabled");
    }

    // ---- errors of the contract ---------------------------------------------------

    static Stream<Arguments> serviceErrors() {
        return Stream.of(
                Arguments.of(CatalogConfigurationException.badRequest(List.of(new Violation("enabled", "is required"))),
                        400, "BAD_REQUEST"),
                Arguments.of(new UnknownSchemaException(DOCTORID_URI), 400, "unknown_schema"),
                Arguments.of(new UnsupportedBindingTypeException(DOCTORID_URI), 400, "unsupported_binding_type"),
                Arguments.of(new CatalogConfigurationException("field_not_in_schema", "Field [nationalId] is not in the schema",
                        List.of(new Violation("search_identifiers[1].field", "is not in the schema"))), 400, "field_not_in_schema"),
                Arguments.of(new CatalogConfigurationException("invalid_validity", "The default validity is above the maximum",
                        List.of(new Violation("validity.default_days", "is above validity.max_days"))), 400, "invalid_validity"),
                Arguments.of(new CatalogConfigurationException("no_delivery_mode", "An enabled entry needs at least one delivery mode",
                        List.of(new Violation("delivery_modes", "must not be empty when the entry is enabled"))), 400, "no_delivery_mode"),
                Arguments.of(new TenantNotResolvedException("Tenant context not resolved"), 403, "tenant_not_resolved"),
                Arguments.of(new CatalogEntryNotFoundException(ID), 404, "catalog_entry_not_found"),
                Arguments.of(new CatalogEntryAlreadyExistsException(ID, new RuntimeException()), 409, "catalog_entry_already_exists"),
                Arguments.of(new PreconditionFailedException("If-Match does not match"), 412, "precondition_failed"),
                Arguments.of(new PreconditionRequiredException("The If-Match header is required"), 428, "precondition_required"));
    }

    @ParameterizedTest
    @MethodSource("serviceErrors")
    void get_whenTheServiceFails_answersAProblemWithThatType(Exception error, int status, String type) {
        when(service.get(ID)).thenReturn(Mono.error(error));

        assertProblem(webTestClient.get().uri(ENTRY_PATH).header("Authorization", BEARER).exchange(),
                status, type, ENTRY_PATH);
    }

    @ParameterizedTest
    @MethodSource("serviceErrors")
    void create_whenTheServiceFails_answersAProblemWithThatType(Exception error, int status, String type) {
        when(service.create(any())).thenReturn(Mono.error(error));

        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(DOCTORID_CREATE_BODY)
                        .exchange(),
                status, type, ATTESTATION_CATALOG_PATH);
    }

    @Test
    void invalidConfiguration_carriesTheViolationsAndTheTitleOfTheContractExample() {
        when(service.create(any())).thenReturn(Mono.error(new CatalogConfigurationException(
                "field_not_in_schema", "Field [nationalId] is not in the schema",
                List.of(new Violation("search_identifiers[1].field", "is not in the schema")))));

        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(DOCTORID_CREATE_BODY)
                        .exchange(),
                400, "field_not_in_schema", ATTESTATION_CATALOG_PATH)
                .jsonPath("$.title").isEqualTo("Field not in schema")
                .jsonPath("$.status").isEqualTo(400)
                .jsonPath("$.detail").isEqualTo("Field [nationalId] is not in the schema")
                .jsonPath("$.violations[0].field").isEqualTo("search_identifiers[1].field")
                .jsonPath("$.violations[0].message").isEqualTo("is not in the schema");
    }

    @Test
    void invalidToken_thrownFromTheController_isUnauthorizedProblem() {
        when(catalogPdpService.authorizeRead(anyString())).thenReturn(Mono.error(new InvalidTokenException()));

        assertProblem(webTestClient.get().uri(ENTRY_PATH).header("Authorization", BEARER).exchange(),
                401, "invalid_token", ENTRY_PATH);
    }

    @Test
    void insufficientPermission_carriesTheDetailOfThePdp() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new InsufficientPermissionException("Only the tenant administrator can modify the catalog")));

        assertProblem(webTestClient.mutateWith(csrf()).patch().uri(ENTRY_PATH)
                        .header("Authorization", BEARER)
                        .header("If-Match", "\"1\"")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{\"enabled\": true}")
                        .exchange(),
                403, "insufficient_permission", ENTRY_PATH)
                .jsonPath("$.detail").isEqualTo("Only the tenant administrator can modify the catalog");
        verify(service, never()).setEnabled(anyString(), org.mockito.ArgumentMatchers.anyBoolean(), any());
    }

    @Test
    void tenantMismatch_isForbiddenProblem() {
        when(catalogPdpService.authorizeRead(anyString()))
                .thenReturn(Mono.error(new TenantMismatchException("Token tenant 'a' does not match tenant header 'b'")));

        assertProblem(webTestClient.get().uri(ATTESTATION_CATALOG_PATH).header("Authorization", BEARER).exchange(),
                403, "tenant_mismatch", ATTESTATION_CATALOG_PATH)
                .jsonPath("$.detail").value(detail -> assertThat(String.valueOf(detail)).doesNotContain("'a'"));
    }

    @Test
    void unexpectedError_isInternalServerErrorWithoutInternalDetail() {
        when(service.get(ID)).thenReturn(Mono.error(new IllegalStateException("password=hunter2 at jdbc:postgresql://db")));

        assertProblem(webTestClient.get().uri(ENTRY_PATH).header("Authorization", BEARER).exchange(),
                500, "INTERNAL_SERVER_ERROR", ENTRY_PATH)
                .jsonPath("$.detail").isEqualTo("An unexpected error occurred");
    }

    // ---- the PDP goes before the body ----------------------------------------------

    @ParameterizedTest
    @MethodSource("bodiesAnOperatorMightSend")
    void write_asOperator_isInsufficientPermissionWhateverTheBodyIs(String body) {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new InsufficientPermissionException("Only the tenant administrator can modify the catalog")));

        assertProblem(webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                        .header("Authorization", BEARER)
                        .header("If-Match", "\"1\"")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(body)
                        .exchange(),
                403, "insufficient_permission", ENTRY_PATH);
        verify(service, never()).replace(anyString(), any(), any());
    }

    static Stream<String> bodiesAnOperatorMightSend() {
        return Stream.of(
                "{this is not json",
                "{\"validity\": {\"default_days\": \"many\"}}",
                "{\"enabled\": true, \"delivery_modes\": [], \"validity\": {\"default_days\": 0, \"requester_can_set_dates\": false}}",
                "[]");
    }

    @Test
    void create_asOperator_doesNotEvenReadTheBody() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new InsufficientPermissionException("Only the tenant administrator can modify the catalog")));

        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{this is not json")
                        .exchange(),
                403, "insufficient_permission", ATTESTATION_CATALOG_PATH);
    }

    // ---- a write the PDP denies is audited as denied ------------------------------------

    @Test
    void replace_deniedByThePdp_auditsADeniedUpdateOfTheEntry() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new InsufficientPermissionException("Only the tenant administrator can modify the catalog")));

        webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", "\"1\"")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isForbidden();

        verify(changeAuditor).auditDenied(CatalogEntryChange.Operation.UPDATE, ID, "PolicyDenied");
    }

    @Test
    void create_deniedByThePdp_auditsADeniedCreateWithoutTheEntry() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new InsufficientPermissionException("Only the tenant administrator can modify the catalog")));

        webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                .header("Authorization", BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isForbidden();

        verify(changeAuditor).auditDenied(CatalogEntryChange.Operation.CREATE, null, "PolicyDenied");
    }

    @Test
    void patch_deniedByThePdp_auditsADeniedWriteWithoutTheOperationBecauseTheBodyIsNotRead() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new InsufficientPermissionException("Only the tenant administrator can modify the catalog")));

        webTestClient.mutateWith(csrf()).patch().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", "\"1\"")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabled\": false}")
                .exchange()
                .expectStatus().isForbidden();

        verify(changeAuditor).auditDenied(null, ID, "PolicyDenied");
    }

    @Test
    void write_withATokenOfAnotherTenant_isAlsoAuditedAsDenied() {
        when(catalogPdpService.authorizeWrite(anyString()))
                .thenReturn(Mono.error(new TenantMismatchException("Token tenant 'a' does not match tenant header 'b'")));

        webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", "\"1\"")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isForbidden();

        verify(changeAuditor).auditDenied(CatalogEntryChange.Operation.UPDATE, ID, "PolicyDenied");
    }

    @Test
    void write_withAnInvalidToken_isNotAuditedAsDenied() {
        when(catalogPdpService.authorizeWrite(anyString())).thenReturn(Mono.error(new InvalidTokenException()));

        webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                .header("Authorization", BEARER)
                .header("If-Match", "\"1\"")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isUnauthorized();

        verify(changeAuditor, never()).auditDenied(any(), any(), any());
    }

    // ---- bodies that cannot be read, once the caller is allowed ----------------------

    @Test
    void create_withMalformedJson_isBadRequestProblem() {
        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{this is not json")
                        .exchange(),
                400, "BAD_REQUEST", ATTESTATION_CATALOG_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("body")
                .jsonPath("$.violations[0].message").isEqualTo("is not valid JSON");
        verify(service, never()).create(any());
    }

    @Test
    void create_withAListInsteadOfAnObject_isAViolationOnTheBody() {
        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("[]")
                        .exchange(),
                400, "BAD_REQUEST", ATTESTATION_CATALOG_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("body")
                .jsonPath("$.violations[0].message").isEqualTo("has an invalid value");
        verify(service, never()).create(any());
    }

    @Test
    void create_withAValueOfTheWrongType_namesItInAViolation() {
        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(createBodyWith(ENABLED, MODES,
                                "\"validity\": {\"default_days\": \"many\", \"requester_can_set_dates\": false}"))
                        .exchange(),
                400, "BAD_REQUEST", ATTESTATION_CATALOG_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("validity.default_days");
    }

    @Test
    void replace_withoutBody_isBadRequestProblem() {
        assertProblem(webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                        .header("Authorization", BEARER)
                        .header("If-Match", "\"1\"")
                        .contentType(MediaType.APPLICATION_JSON)
                        .exchange(),
                400, "BAD_REQUEST", ENTRY_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("body")
                .jsonPath("$.violations[0].message").isEqualTo("is required");
    }

    @Test
    void create_withoutBody_isAViolationOnTheBody() {
        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .exchange(),
                400, "BAD_REQUEST", ATTESTATION_CATALOG_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("body")
                .jsonPath("$.violations[0].message").isEqualTo("is required");
    }

    @Test
    void patch_withoutBody_isAViolationOnTheBody() {
        assertProblem(webTestClient.mutateWith(csrf()).patch().uri(ENTRY_PATH)
                        .header("Authorization", BEARER)
                        .header("If-Match", "\"1\"")
                        .contentType(MediaType.APPLICATION_JSON)
                        .exchange(),
                400, "BAD_REQUEST", ENTRY_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("body");
    }

    @Test
    void create_withAnotherMediaType_isUnsupportedMediaTypeProblem() {
        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.TEXT_PLAIN)
                        .bodyValue("hello")
                        .exchange(),
                415, "UNSUPPORTED_MEDIA_TYPE", ATTESTATION_CATALOG_PATH);
    }

    // ---- unknown fields (the validator turns them into violations; here they must reach it) ----

    /**
     * The service is the real validator behind a mock persistence: shape violations are reported before
     * anything else is looked at, so this proves HTTP body to violation end to end.
     */
    @Test
    void create_withAnUnknownTopLevelField_isBadRequest() {
        whenCreatingValidate();

        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(createBodyWith(CONFIGURATION, "\"credential_configuration_id\": \"doctorid.sd.1\""))
                        .exchange(),
                400, "BAD_REQUEST", ATTESTATION_CATALOG_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("credential_configuration_id");
    }

    @Test
    void create_withAnUnknownFieldInsideValidity_isBadRequest() {
        whenCreatingValidate();

        assertProblem(webTestClient.mutateWith(csrf()).post().uri(ATTESTATION_CATALOG_PATH)
                        .header("Authorization", BEARER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(createBodyWith(ENABLED, MODES,
                                "\"validity\": {\"default_days\": 5, \"requester_can_set_dates\": false, \"min_days\": 1}"))
                        .exchange(),
                400, "BAD_REQUEST", ATTESTATION_CATALOG_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("validity.min_days");
    }

    @Test
    void replace_withAnUnknownFieldInsideASearchIdentifier_isBadRequest() {
        whenReplacingValidate();

        assertProblem(webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                        .header("Authorization", BEARER)
                        .header("If-Match", "\"1\"")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("""
                                {"enabled": true, "delivery_modes": ["email"],
                                 "validity": {"default_days": 5, "requester_can_set_dates": false},
                                 "search_identifiers": [{"name": "colegiado", "field": ["x"], "label": "Nº"}]}""")
                        .exchange(),
                400, "BAD_REQUEST", ENTRY_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("search_identifiers[0].label");
    }

    @Test
    void replace_withAnUnknownDeliveryMode_isBadRequestWithAViolationOnItsIndex() {
        whenReplacingValidate();

        assertProblem(webTestClient.mutateWith(csrf()).put().uri(ENTRY_PATH)
                        .header("Authorization", BEARER)
                        .header("If-Match", "\"1\"")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("""
                                {"enabled": true, "delivery_modes": ["email", "carrier-pigeon"],
                                 "validity": {"default_days": 5, "requester_can_set_dates": false}}""")
                        .exchange(),
                400, "BAD_REQUEST", ENTRY_PATH)
                .jsonPath("$.violations[0].field").isEqualTo("delivery_modes[1]");
    }

    // ---- helpers -------------------------------------------------------------------

    private static final String ENABLED = "\"enabled\": true";
    private static final String MODES = "\"delivery_modes\": [\"email\", \"ui\"]";
    private static final String VALIDITY = "\"validity\": {\"default_days\": 36500, \"requester_can_set_dates\": false}";
    private static final String SUBJECT = "\"subject\": {\"fields\": [[\"givenName\"], [\"familyName\"]], \"separator\": \" \"}";
    private static final String IDENTIFIERS =
            "\"search_identifiers\": [{\"name\": \"colegiado\", \"field\": [\"personal_administrative_number\"]}]";

    /** The configuration of the contract's DoctorID example. */
    private static final String CONFIGURATION = String.join(", ", ENABLED, MODES, VALIDITY, SUBJECT, IDENTIFIERS);

    private static final String DOCTORID_CREATE_BODY = createBodyWith(CONFIGURATION);

    private static String createBodyWith(String... members) {
        return "{\"schema_uri\": \"" + DOCTORID_URI + "\", " + String.join(", ", members) + "}";
    }

    private void whenCreatingValidate() {
        CatalogEntryValidator validator = validatorOf(Optional.of(ID));
        when(service.create(any())).thenAnswer(invocation -> {
            CreateCatalogEntryCommand command = invocation.getArgument(0);
            return Mono.fromSupplier(() -> validator.validateForCreate(command));
        });
    }

    private void whenReplacingValidate() {
        CatalogEntryValidator validator = validatorOf(Optional.of(ID));
        when(service.replace(eq(ID), any(), any())).thenAnswer(invocation -> {
            CatalogConfigurationInput input = invocation.getArgument(1);
            return Mono.fromSupplier(() -> validator.validateForReplace(ID, input));
        });
    }

    private static CatalogEntryValidator validatorOf(Optional<String> resolvedId) {
        CredentialProfileCatalog catalog = mock(CredentialProfileCatalog.class);
        when(catalog.resolveSchemaUri(anyString())).thenReturn(resolvedId);
        when(catalog.getByConfigurationId(ID)).thenReturn(mock(CredentialProfile.class));
        SchemaDeliveryCeiling ceiling = mock(SchemaDeliveryCeiling.class);
        when(ceiling.resolveEligibleModes(ID)).thenReturn(Set.of(DeliveryMode.values()));
        return new CatalogEntryValidator(catalog, ceiling);
    }

    private static WebTestClient.BodyContentSpec assertProblem(
            WebTestClient.ResponseSpec response, int status, String type, String instance) {
        return response
                .expectStatus().isEqualTo(status)
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo(type)
                .jsonPath("$.status").isEqualTo(status)
                .jsonPath("$.instance").isEqualTo(instance);
    }

    private static CatalogEntry doctorId(long version) {
        return new CatalogEntry(ID, DOCTORID_URI, true, Set.of(DeliveryMode.EMAIL, DeliveryMode.UI),
                new CatalogEntry.Validity(36500, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("givenName"), ClaimPath.of("familyName")), " "),
                List.of(new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("personal_administrative_number"))),
                version, Instant.parse("2026-10-19T08:00:00Z"), Instant.parse("2026-10-19T09:30:00Z"));
    }
}
