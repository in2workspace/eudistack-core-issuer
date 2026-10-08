package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.ConcurrentIssuanceUpdateException;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Covers status transitions, optimistic-locking conflict mapping, the platform cross-tenant view,
 * credential id extraction and credential-offer email resolution of {@link IssuanceServiceImpl}.
 */
@ExtendWith(MockitoExtension.class)
class IssuanceServiceImplBranchesTest {

    private static final UUID ISSUANCE_UUID = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
    private static final String ISSUANCE_ID = ISSUANCE_UUID.toString();
    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String SYS_TENANT = "sys-tenant";

    @Mock
    private IssuerProperties appConfig;
    @Mock
    private IssuancePort issuancePort;
    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;
    @Mock
    private TenantRegistryService tenantRegistryService;

    private IssuanceServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new IssuanceServiceImpl(appConfig, issuancePort, new ObjectMapper(),
                credentialProfileRegistry, tenantRegistryService);
        lenient().when(appConfig.getSysTenant()).thenReturn(SYS_TENANT);
    }

    // --- getCredentialTypeByIssuanceId ---

    @Test
    void getCredentialTypeByIssuanceId_withVcWrapper_readsNestedType() {
        when(issuancePort.findById(ISSUANCE_UUID)).thenReturn(Mono.just(issuance(
                CredentialStatusEnum.DRAFT, "{\"vc\":{\"type\":[\"VerifiableAttestation\",\"LEARCredential\"]}}")));

        StepVerifier.create(service.getCredentialTypeByIssuanceId(ISSUANCE_ID))
                .expectNext("LEARCredential")
                .verifyComplete();
    }

    // --- extractCredentialId ---

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "{\"vc\":{\"id\":\"urn:vc\"},\"id\":\"urn:top\"}  | urn:vc",
            "{\"vc\":{\"id\":\" \"},\"id\":\"urn:top\"}       | urn:top",
            "{\"id\":\"urn:top\",\"jti\":\"jti-1\"}           | urn:top",
            "{\"id\":\"\",\"jti\":\"jti-1\"}                  | jti-1"
    })
    void extractCredentialId_resolvesFirstAvailableIdentifier(String json, String expected) {
        StepVerifier.create(service.extractCredentialId(issuance(CredentialStatusEnum.DRAFT, json)))
                .expectNext(expected)
                .verifyComplete();
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"jti\":\" \"}"})
    void extractCredentialId_withoutIdentifier_completesEmpty(String json) {
        StepVerifier.create(service.extractCredentialId(issuance(CredentialStatusEnum.DRAFT, json)))
                .verifyComplete();
    }

    // --- status transitions ---

    static Stream<Arguments> validTransitions() {
        return Stream.of(
                Arguments.of(Named.of("ISSUED -> VALID", (Function<IssuanceServiceImpl, Mono<Void>>)
                        s -> s.updateIssuanceStatusToValidByIssuanceId(ISSUANCE_ID)),
                        CredentialStatusEnum.ISSUED, CredentialStatusEnum.VALID),
                Arguments.of(Named.of("DRAFT -> WITHDRAWN", (Function<IssuanceServiceImpl, Mono<Void>>)
                        s -> s.withdrawIssuance(ISSUANCE_ID)),
                        CredentialStatusEnum.DRAFT, CredentialStatusEnum.WITHDRAWN));
    }

    @ParameterizedTest
    @MethodSource("validTransitions")
    void statusUpdate_withAllowedTransition_savesNewStatus(Function<IssuanceServiceImpl, Mono<Void>> operation,
                                                           CredentialStatusEnum from, CredentialStatusEnum to) {
        // Arrange
        Issuance issuance = issuance(from, "{}");
        when(issuancePort.findByIssuanceId(ISSUANCE_UUID)).thenReturn(Mono.just(issuance));
        when(issuancePort.save(issuance)).thenReturn(Mono.just(issuance));

        // Act + Assert
        StepVerifier.create(operation.apply(service)).verifyComplete();
        assertThat(issuance.getCredentialStatus()).isEqualTo(to);
    }

    static Stream<Arguments> forbiddenTransitions() {
        return Stream.of(
                Arguments.of(Named.of("DRAFT -> VALID", (Function<IssuanceServiceImpl, Mono<Void>>)
                        s -> s.updateIssuanceStatusToValidByIssuanceId(ISSUANCE_ID)), CredentialStatusEnum.DRAFT),
                Arguments.of(Named.of("VALID -> WITHDRAWN", (Function<IssuanceServiceImpl, Mono<Void>>)
                        s -> s.withdrawIssuance(ISSUANCE_ID)), CredentialStatusEnum.VALID));
    }

    @ParameterizedTest
    @MethodSource("forbiddenTransitions")
    void statusUpdate_withForbiddenTransition_errors(Function<IssuanceServiceImpl, Mono<Void>> operation,
                                                     CredentialStatusEnum from) {
        when(issuancePort.findByIssuanceId(ISSUANCE_UUID)).thenReturn(Mono.just(issuance(from, "{}")));

        StepVerifier.create(operation.apply(service))
                .expectError(InvalidCredentialStatusTransitionException.class)
                .verify();
    }

    static Stream<Arguments> conflictingWrites() {
        return Stream.of(
                Arguments.of(Named.of("updateIssuanceStatusToValidByIssuanceId", (Function<IssuanceServiceImpl, Mono<?>>)
                        s -> s.updateIssuanceStatusToValidByIssuanceId(ISSUANCE_ID)), CredentialStatusEnum.ISSUED),
                Arguments.of(Named.of("withdrawIssuance", (Function<IssuanceServiceImpl, Mono<?>>)
                        s -> s.withdrawIssuance(ISSUANCE_ID)), CredentialStatusEnum.DRAFT),
                Arguments.of(Named.of("archiveIssuance", (Function<IssuanceServiceImpl, Mono<?>>)
                        s -> s.archiveIssuance(ISSUANCE_ID)), CredentialStatusEnum.WITHDRAWN));
    }

    @ParameterizedTest
    @MethodSource("conflictingWrites")
    void statusUpdate_whenSaveConflicts_relabelsConflictWithOperation(Function<IssuanceServiceImpl, Mono<?>> operation,
                                                                     CredentialStatusEnum from) {
        // Arrange
        when(issuancePort.findByIssuanceId(ISSUANCE_UUID)).thenReturn(Mono.just(issuance(from, "{}")));
        when(issuancePort.save(any())).thenReturn(Mono.error(conflict()));

        // Act + Assert
        StepVerifier.create(operation.apply(service))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ConcurrentIssuanceUpdateException.class)
                        .hasMessageContaining(ISSUANCE_ID))
                .verify();
    }

    @Test
    void updateCredentialDataSetByIssuanceId_whenSaveConflicts_relabelsConflict() {
        when(issuancePort.findById(ISSUANCE_UUID)).thenReturn(Mono.just(issuance(CredentialStatusEnum.DRAFT, "{}")));
        when(issuancePort.save(any())).thenReturn(Mono.error(conflict()));

        StepVerifier.create(service.updateCredentialDataSetByIssuanceId(ISSUANCE_ID, "{}", "jwt_vc_json"))
                .expectErrorSatisfies(e -> assertThat(e).hasMessageContaining("updateCredentialDataSetByIssuanceId"))
                .verify();
    }

    @Test
    void updateIssuance_whenSaveConflicts_relabelsConflict() {
        Issuance issuance = issuance(CredentialStatusEnum.DRAFT, "{}");
        when(issuancePort.save(issuance)).thenReturn(Mono.error(conflict()));

        StepVerifier.create(service.updateIssuance(issuance))
                .expectErrorSatisfies(e -> assertThat(e).hasMessageContaining("updateIssuance"))
                .verify();
    }

    @Test
    void updateIssuance_whenSaveSucceeds_returnsSaved() {
        Issuance issuance = issuance(CredentialStatusEnum.DRAFT, "{}");
        when(issuancePort.save(issuance)).thenReturn(Mono.just(issuance));

        StepVerifier.create(service.updateIssuance(issuance))
                .expectNext(issuance)
                .verifyComplete();
    }

    // --- platform cross-tenant view ---

    @Test
    void getIssuanceDetail_asPlatformSysAdmin_searchesAcrossTenants() {
        // Arrange
        AuthorizationContext ctx = new AuthorizationContext("ORG", UserRole.SYSADMIN, true, "PLATFORM");
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("acme", "globex")));
        when(issuancePort.findByIssuanceId(ISSUANCE_UUID))
                .thenReturn(Mono.just(issuance(CredentialStatusEnum.VALID, "{\"id\":\"urn:1\"}")));

        // Act + Assert
        StepVerifier.create(service.getIssuanceDetailByIssuanceIdAndOrganizationId(ctx, ISSUANCE_ID))
                .assertNext(details -> {
                    assertThat(details.issuanceId()).isEqualTo(ISSUANCE_UUID);
                    assertThat(details.lifeCycleStatus()).isEqualTo("VALID");
                })
                .verifyComplete();
    }

    @Test
    void getAllIssuancesVisibleFor_asPlatformSysAdmin_listsNonPlatformTenantsSortedByUpdated() {
        // Arrange
        AuthorizationContext ctx = new AuthorizationContext("ORG", UserRole.SYSADMIN, true, "PLATFORM");
        Instant older = Instant.parse("2025-01-01T00:00:00Z");
        Instant newer = Instant.parse("2026-01-01T00:00:00Z");
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("platform", "acme")));
        when(issuancePort.findAllOrderByUpdatedDesc()).thenReturn(Flux.just(
                summaryIssuance(older), summaryIssuance(newer), summaryIssuance(null)));

        // Act + Assert
        StepVerifier.create(service.getAllIssuancesVisibleFor(ctx))
                .assertNext(list -> {
                    assertThat(list.issuances()).hasSize(3);
                    assertThat(list.issuances()).extracting(e -> e.issuance().tenant()).containsOnly("acme");
                    assertThat(list.issuances().stream().map(IssuanceList.IssuanceEntry::issuance)
                            .filter(s -> s.updated() != null).map(s -> s.updated()).toList())
                            .containsExactly(newer, older);
                })
                .verifyComplete();
    }

    @Test
    void getAllIssuancesVisibleFor_asPlatformSysAdminWithInvalidJson_errors() {
        AuthorizationContext ctx = new AuthorizationContext("ORG", UserRole.SYSADMIN, true, "PLATFORM");
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("acme")));
        when(issuancePort.findAllOrderByUpdatedDesc())
                .thenReturn(Flux.just(issuance(CredentialStatusEnum.DRAFT, "{not json")));

        StepVerifier.create(service.getAllIssuancesVisibleFor(ctx))
                .expectError(ParseCredentialJsonException.class)
                .verify();
    }

    @Test
    void getAllIssuanceSummariesByOrganizationId_withInvalidJson_errors() {
        when(issuancePort.findAllByOrganizationIdentifier("ORG"))
                .thenReturn(Flux.just(issuance(CredentialStatusEnum.DRAFT, "{not json")));

        StepVerifier.create(service.getAllIssuanceSummariesByOrganizationId("ORG"))
                .expectError(ParseCredentialJsonException.class)
                .verify();
    }

    // --- credential offer email info ---

    @Test
    void findCredentialOfferEmailInfo_withUnknownProfile_errors() {
        when(issuancePort.findByIssuanceId(ISSUANCE_UUID)).thenReturn(Mono.just(issuance(CredentialStatusEnum.DRAFT, "{}")));

        StepVerifier.create(service.findCredentialOfferEmailInfoByIssuanceId(ISSUANCE_ID))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(FormatUnsupportedException.class)
                        .hasMessageContaining(CONFIG_ID))
                .verify();
    }

    static Stream<Arguments> emailOrganizationCases() {
        String credential = "{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organization\":\"ACME Corp\"}}}}";
        String orgIdPath = "credentialSubject.mandate.mandator.organizationIdentifier";
        return Stream.of(
                Arguments.of(Named.of("strategy none", profile("none", orgIdPath)), credential, SYS_TENANT),
                Arguments.of(Named.of("mandator organization", profile("field", orgIdPath)), credential, "ACME Corp"),
                Arguments.of(Named.of("mandator without organization", profile("field", orgIdPath)),
                        "{\"credentialSubject\":{\"mandate\":{\"mandator\":{}}}}", SYS_TENANT),
                Arguments.of(Named.of("mandator path missing", profile("field", orgIdPath)),
                        "{\"credentialSubject\":{}}", SYS_TENANT),
                Arguments.of(Named.of("no validation", CredentialProfile.builder()
                        .organizationExtraction(new CredentialProfile.OrganizationExtraction("field", "x")).build()),
                        credential, SYS_TENANT),
                Arguments.of(Named.of("validation without org path", CredentialProfile.builder()
                        .organizationExtraction(new CredentialProfile.OrganizationExtraction("field", "x"))
                        .validation(new CredentialProfile.Validation(null)).build()),
                        credential, SYS_TENANT),
                Arguments.of(Named.of("top-level org path", profile("field", "organizationIdentifier")),
                        credential, SYS_TENANT));
    }

    @ParameterizedTest
    @MethodSource("emailOrganizationCases")
    void findCredentialOfferEmailInfo_resolvesOrganization(CredentialProfile profile, String credential,
                                                          String expectedOrganization) {
        // Arrange
        when(issuancePort.findByIssuanceId(ISSUANCE_UUID))
                .thenReturn(Mono.just(issuance(CredentialStatusEnum.DRAFT, credential)));
        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);

        // Act + Assert
        StepVerifier.create(service.findCredentialOfferEmailInfoByIssuanceId(ISSUANCE_ID))
                .assertNext(info -> {
                    assertThat(info.email()).isEqualTo("user@example.com");
                    assertThat(info.organization()).isEqualTo(expectedOrganization);
                })
                .verifyComplete();
    }

    @Test
    void findCredentialOfferEmailInfo_withInvalidCredentialJson_errors() {
        when(issuancePort.findByIssuanceId(ISSUANCE_UUID))
                .thenReturn(Mono.just(issuance(CredentialStatusEnum.DRAFT, "{not json")));
        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID))
                .thenReturn(profile("field", "credentialSubject.mandate.mandator.organizationIdentifier"));

        StepVerifier.create(service.findCredentialOfferEmailInfoByIssuanceId(ISSUANCE_ID))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ParseCredentialJsonException.class)
                        .hasMessageContaining(ISSUANCE_ID))
                .verify();
    }

    // --- pass-through queries ---

    @Test
    void passThroughQueries_delegateToPort() {
        // Arrange
        Instant now = Instant.now();
        Issuance issuance = issuance(CredentialStatusEnum.ISSUED, "{}");
        when(issuancePort.findByCredentialOfferRefreshToken("rt")).thenReturn(Mono.just(issuance));
        when(issuancePort.findIssuedReadyForActivation(CredentialStatusEnum.ISSUED, now)).thenReturn(Flux.just(issuance));
        when(issuancePort.findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum.DRAFT, now)).thenReturn(Flux.just(issuance));
        when(issuancePort.findFailedDeliveries(now)).thenReturn(Flux.just(issuance));

        // Act + Assert
        StepVerifier.create(service.getIssuanceByCredentialOfferRefreshToken("rt")).expectNext(issuance).verifyComplete();
        StepVerifier.create(service.findIssuedReadyForActivation(now)).expectNext(issuance).verifyComplete();
        StepVerifier.create(service.findStaleDrafts(now)).expectNext(issuance).verifyComplete();
        StepVerifier.create(service.findFailedDeliveries(now)).expectNext(issuance).verifyComplete();
    }

    @Test
    void saveIssuance_whenInsertFails_propagatesError() {
        Issuance issuance = issuance(CredentialStatusEnum.DRAFT, "{}");
        when(issuancePort.insert(issuance)).thenReturn(Mono.error(new IllegalStateException("db down")));

        StepVerifier.create(service.saveIssuance(issuance))
                .expectErrorMessage("db down")
                .verify();
    }

    // --- helpers ---

    private static Issuance issuance(CredentialStatusEnum status, String dataSet) {
        return Issuance.builder()
                .issuanceId(ISSUANCE_UUID)
                .credentialType(CONFIG_ID)
                .credentialStatus(status)
                .credentialDataSet(dataSet)
                .email("user@example.com")
                .build();
    }

    private static Issuance summaryIssuance(Instant updatedAt) {
        Issuance issuance = issuance(CredentialStatusEnum.VALID, "{}");
        issuance.setUpdatedAt(updatedAt);
        return issuance;
    }

    private static CredentialProfile profile(String strategy, String mandatorOrgIdPath) {
        return CredentialProfile.builder()
                .organizationExtraction(new CredentialProfile.OrganizationExtraction(strategy, "x"))
                .validation(new CredentialProfile.Validation(mandatorOrgIdPath))
                .build();
    }

    private static ConcurrentIssuanceUpdateException conflict() {
        return new ConcurrentIssuanceUpdateException(ISSUANCE_UUID, "save", new IllegalStateException("version"));
    }
}
