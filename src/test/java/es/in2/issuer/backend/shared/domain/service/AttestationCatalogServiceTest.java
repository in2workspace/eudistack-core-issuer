package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.PreconditionFailedException;
import es.in2.issuer.backend.shared.domain.exception.PreconditionRequiredException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.exception.UnknownSchemaException;
import es.in2.issuer.backend.shared.domain.exception.UnsupportedBindingTypeException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.SearchIdentifierInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.SubjectInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.ValidityInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryChange;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.catalog.CreateCatalogEntryCommand;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link AttestationCatalogService} over a mocked {@link CatalogEntryPort}, with the real validator
 * and filler on the credential types of {@code src/test/resources/catalog-profiles}.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AttestationCatalogServiceTest {

    private static final String TENANT = "demo";
    private static final String DOCTORID = "doctorid.sd.1";
    private static final String DOCTORID_URI = "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt";
    private static final String LEAR = "learcredential.employee.sd.1";
    private static final String LEAR_SYNTHETIC_URI = "https://registry.eudistack.net/schemas/" + LEAR;

    private static final CredentialProfileRegistry REGISTRY = new CredentialProfileRegistry(
            JsonMapper.builder().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false).build(),
            new PathMatchingResourcePatternResolver(), "classpath:catalog-profiles");

    @Mock private CatalogEntryPort port;
    @Mock private TenantCredentialProfileService tenantCredentialProfileService;
    @Mock private TransactionalOperator transactionalOperator;
    @Mock private CatalogEntryChangeAuditor changeAuditor;

    private AttestationCatalogService service;

    @BeforeEach
    void setUp() {
        SchemaDeliveryCeiling ceiling = new SchemaDeliveryCeiling(REGISTRY);
        service = new AttestationCatalogService(port, new CatalogEntryFiller(REGISTRY, ceiling),
                new CatalogEntryValidator(REGISTRY, ceiling), REGISTRY, tenantCredentialProfileService,
                transactionalOperator, changeAuditor);
        when(changeAuditor.audit(any())).thenReturn(Mono.empty());
        when(transactionalOperator.transactional(any(Mono.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    // ---- create ----------------------------------------------------------------

    @Test
    void create_storesTheValidatedEntry_andDropsTheCacheAfterwards() {
        when(port.insert(any())).thenAnswer(inv -> Mono.just(stored(inv.getArgument(0), 0)));

        StepVerifier.create(inTenant(service.create(createDoctorId())))
                .assertNext(created -> {
                    assertThat(created.credentialConfigurationId()).isEqualTo(DOCTORID);
                    assertThat(created.schemaUri()).isEqualTo(DOCTORID_URI);
                })
                .verifyComplete();

        ArgumentCaptor<CatalogEntry> inserted = ArgumentCaptor.forClass(CatalogEntry.class);
        verify(port).insert(inserted.capture());
        assertThat(inserted.getValue().validity()).isEqualTo(new CatalogEntry.Validity(36500, false, null));
        verify(tenantCredentialProfileService).invalidateCache(TENANT);
    }

    @Test
    void create_auditsTheCreationAfterTheCommit() {
        when(port.insert(any())).thenAnswer(inv -> Mono.just(stored(inv.getArgument(0), 0)));

        StepVerifier.create(inTenant(service.create(createDoctorId()))).expectNextCount(1).verifyComplete();

        InOrder order = inOrder(tenantCredentialProfileService, changeAuditor);
        order.verify(tenantCredentialProfileService).invalidateCache(TENANT);
        ArgumentCaptor<CatalogEntryChange> change = ArgumentCaptor.forClass(CatalogEntryChange.class);
        order.verify(changeAuditor).audit(change.capture());
        assertThat(change.getValue().action()).isEqualTo(CatalogEntryChange.Action.CREATE);
        assertThat(change.getValue().before()).isNull();
        assertThat(change.getValue().credentialConfigurationId()).isEqualTo(DOCTORID);
        assertThat(change.getValue().version()).isZero();
    }

    @Test
    void create_whenRejected_auditsNothing() {
        StepVerifier.create(inTenant(service.create(new CreateCatalogEntryCommand(
                        "https://registry.eudistack.net/schemas/nobody/1.0.0/dc+sd-jwt", doctorIdConfiguration().toInput()))))
                .expectError(UnknownSchemaException.class)
                .verify();

        verify(changeAuditor, never()).audit(any());
    }

    @Test
    void create_ofATypeWithoutDeclaredSchemaUri_auditsTheSyntheticOne() {
        when(port.insert(any())).thenAnswer(inv -> Mono.just(stored(inv.getArgument(0), 0)));

        StepVerifier.create(inTenant(service.create(new CreateCatalogEntryCommand(LEAR_SYNTHETIC_URI,
                        doctorIdConfiguration().withSubject(null).withIdentifiers(List.of()).toInput()))))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<CatalogEntryChange> change = ArgumentCaptor.forClass(CatalogEntryChange.class);
        verify(changeAuditor).audit(change.capture());
        assertThat(change.getValue().after().schemaUri()).isEqualTo(LEAR_SYNTHETIC_URI);
    }

    @Test
    void create_ofATypeWithoutDeclaredSchemaUri_answersWithTheSyntheticOne() {
        when(port.insert(any())).thenAnswer(inv -> Mono.just(stored(inv.getArgument(0), 0)));

        StepVerifier.create(inTenant(service.create(new CreateCatalogEntryCommand(LEAR_SYNTHETIC_URI,
                        doctorIdConfiguration().withSubject(null).withIdentifiers(List.of()).toInput()))))
                .assertNext(created -> assertThat(created.schemaUri()).isEqualTo(LEAR_SYNTHETIC_URI))
                .verifyComplete();

        ArgumentCaptor<CatalogEntry> inserted = ArgumentCaptor.forClass(CatalogEntry.class);
        verify(port).insert(inserted.capture());
        assertThat(inserted.getValue().schemaUri()).as("the synthetic URI is never stored").isNull();
    }

    @Test
    void create_withAnUnknownSchema_isUnknownSchema() {
        StepVerifier.create(inTenant(service.create(new CreateCatalogEntryCommand(
                        "https://registry.eudistack.net/schemas/nobody/1.0.0/dc+sd-jwt", doctorIdConfiguration().toInput()))))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(UnknownSchemaException.class)
                        .extracting(x -> ((CatalogConfigurationException) x).code()).isEqualTo("unknown_schema"))
                .verify();

        verify(port, never()).insert(any());
    }

    @Test
    void create_ofATypeWithAnUnsupportedBinding_isUnsupportedBindingType() {
        StepVerifier.create(inTenant(service.create(new CreateCatalogEntryCommand(
                        "https://registry.eudistack.net/schemas/synthetic.x509-binding.sd.1",
                        doctorIdConfiguration().withSubject(null).withIdentifiers(List.of()).toInput()))))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(UnsupportedBindingTypeException.class)
                        .extracting(x -> ((CatalogConfigurationException) x).code()).isEqualTo("unsupported_binding_type"))
                .verify();
    }

    @Test
    void create_ofASchemaThatAlreadyHasAnEntry_isCatalogEntryAlreadyExists() {
        when(port.insert(any())).thenReturn(Mono.error(new CatalogEntryAlreadyExistsException(DOCTORID, null)));

        StepVerifier.create(inTenant(service.create(createDoctorId())))
                .expectError(CatalogEntryAlreadyExistsException.class)
                .verify();

        verify(tenantCredentialProfileService, never()).invalidateCache(any());
    }

    // ---- get and list ----------------------------------------------------------

    @Test
    void get_ofAnUnknownId_isCatalogEntryNotFound() {
        when(port.findById("nobody")).thenReturn(Mono.empty());

        StepVerifier.create(inTenant(service.get("nobody")))
                .expectError(CatalogEntryNotFoundException.class)
                .verify();
    }

    @Test
    void get_ofAFilledEntry_returnsItWithoutWriting() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(2)));

        StepVerifier.create(inTenant(service.get(DOCTORID)))
                .assertNext(entry -> assertThat(entry.version()).isEqualTo(2))
                .verifyComplete();

        verify(port, never()).updateIfVersion(any(), anyLong());
    }

    /** D13: a row that platform-dev seeded with only its credential_configuration_id. */
    @Test
    void get_ofARowWithOnlyTheCredentialConfigurationId_returnsItCompleteAndStoresIt() {
        CatalogEntry seeded = new CatalogEntry(DOCTORID, null, true, null, null, null, List.of(), 0,
                Instant.now(), Instant.now());
        when(port.findById(DOCTORID)).thenReturn(Mono.just(seeded));
        when(port.updateIfVersion(any(), anyLong())).thenAnswer(inv ->
                Mono.just(Optional.of(stored(inv.getArgument(0), 1))));

        StepVerifier.create(inTenant(service.get(DOCTORID)))
                .assertNext(entry -> {
                    assertThat(entry.isFilled()).isTrue();
                    assertThat(entry.schemaUri()).isEqualTo(DOCTORID_URI);
                    assertThat(entry.deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
                    assertThat(entry.validity()).isEqualTo(new CatalogEntry.Validity(36500, false, null));
                    assertThat(entry.subject().fields())
                            .containsExactly(ClaimPath.of("givenName"), ClaimPath.of("familyName"));
                    assertThat(entry.version()).isEqualTo(1);
                })
                .verifyComplete();

        ArgumentCaptor<CatalogEntry> written = ArgumentCaptor.forClass(CatalogEntry.class);
        verify(port).updateIfVersion(written.capture(), eq(0L));
        assertThat(written.getValue().isFilled()).isTrue();
    }

    @Test
    void get_ofARowSomeoneFilledFirst_readsItAgain() {
        CatalogEntry seeded = new CatalogEntry(DOCTORID, null, true, null, null, null, List.of(), 0,
                Instant.now(), Instant.now());
        when(port.findById(DOCTORID)).thenReturn(Mono.just(seeded)).thenReturn(Mono.just(filledDoctorId(1)));
        when(port.updateIfVersion(any(), anyLong())).thenReturn(Mono.just(Optional.empty()));

        StepVerifier.create(inTenant(service.get(DOCTORID)))
                .assertNext(entry -> assertThat(entry.version()).isEqualTo(1))
                .verifyComplete();
    }

    @Test
    void get_ofAStoredEntryWithoutSchemaUri_answersWithTheSyntheticOne() {
        when(port.findById(LEAR)).thenReturn(Mono.just(filled(LEAR, null, 0)));

        StepVerifier.create(inTenant(service.get(LEAR)))
                .assertNext(entry -> assertThat(entry.schemaUri()).isEqualTo(LEAR_SYNTHETIC_URI))
                .verifyComplete();
    }

    @Test
    void list_withoutFilter_readsEveryEntry() {
        when(port.findAll()).thenReturn(Flux.just(filledDoctorId(0), filled(LEAR, null, 0)));

        StepVerifier.create(service.list(null).contextWrite(tenant()))
                .expectNextCount(2)
                .verifyComplete();
    }

    @Test
    void list_withEnabledFilter_readsOnlyThoseEntries() {
        when(port.findAllByEnabled(false)).thenReturn(Flux.just(filledDoctorId(0)));

        StepVerifier.create(service.list(false).contextWrite(tenant()))
                .expectNextCount(1)
                .verifyComplete();

        verify(port, never()).findAll();
    }

    // ---- replace ---------------------------------------------------------------

    @Test
    void replace_withTheCurrentETag_updatesAndDropsTheCache() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(3)));
        when(port.updateIfVersion(any(), eq(3L))).thenAnswer(inv ->
                Mono.just(Optional.of(stored(inv.getArgument(0), 4))));

        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().withEnabled(false).toInput(), "\"3\"")))
                .assertNext(entry -> {
                    assertThat(entry.version()).isEqualTo(4);
                    assertThat(entry.enabled()).isFalse();
                })
                .verifyComplete();

        verify(tenantCredentialProfileService).invalidateCache(TENANT);
    }

    @Test
    void replace_auditsTheChangeFromTheStoredEntryAfterTheCommit() {
        CatalogEntry current = filledDoctorId(3);
        when(port.findById(DOCTORID)).thenReturn(Mono.just(current));
        when(port.updateIfVersion(any(), eq(3L))).thenAnswer(inv ->
                Mono.just(Optional.of(stored(inv.getArgument(0), 4))));

        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().withEnabled(false).toInput(), "\"3\"")))
                .expectNextCount(1)
                .verifyComplete();

        InOrder order = inOrder(tenantCredentialProfileService, changeAuditor);
        order.verify(tenantCredentialProfileService).invalidateCache(TENANT);
        ArgumentCaptor<CatalogEntryChange> change = ArgumentCaptor.forClass(CatalogEntryChange.class);
        order.verify(changeAuditor).audit(change.capture());
        assertThat(change.getValue().action()).isEqualTo(CatalogEntryChange.Action.REPLACE);
        assertThat(change.getValue().before()).isEqualTo(current);
        assertThat(change.getValue().after().version()).isEqualTo(4);
        assertThat(change.getValue().changes()).containsKeys("enabled", "search_identifiers");
    }

    @Test
    void replace_withTheConfigurationItAlreadyHas_writesAndAuditsNothing() {
        CatalogEntry current = new CatalogEntry(DOCTORID, DOCTORID_URI, true,
                Set.of(DeliveryMode.EMAIL, DeliveryMode.UI), new CatalogEntry.Validity(36500, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("givenName"), ClaimPath.of("familyName")), " "),
                List.of(new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("personal_administrative_number"))),
                3, Instant.now(), Instant.now());
        when(port.findById(DOCTORID)).thenReturn(Mono.just(current));

        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().toInput(), "\"3\"")))
                .assertNext(entry -> assertThat(entry.version()).isEqualTo(3))
                .verifyComplete();

        verify(port, never()).updateIfVersion(any(), anyLong());
        verify(tenantCredentialProfileService, never()).invalidateCache(any());
        verify(changeAuditor, never()).audit(any());
    }

    @Test
    void replace_whenTheVersionIsStale_auditsNothing() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(7)));

        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().toInput(), "\"6\"")))
                .expectError(PreconditionFailedException.class)
                .verify();

        verify(changeAuditor, never()).audit(any());
    }

    @Test
    void replace_withoutIfMatch_isPreconditionRequired() {
        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().toInput(), null)))
                .expectError(PreconditionRequiredException.class)
                .verify();

        verifyNoInteractions(port);
    }

    @Test
    void replace_withIfMatchAny_isPreconditionRequired() {
        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().toInput(), "*")))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(PreconditionRequiredException.class)
                        .hasMessageContaining("send the ETag"))
                .verify();

        verifyNoInteractions(port);
    }

    @Test
    void replace_withAnOldETag_isPreconditionFailed() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(3)));

        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().toInput(), "\"2\"")))
                .expectError(PreconditionFailedException.class)
                .verify();

        verify(port, never()).updateIfVersion(any(), anyLong());
    }

    @Test
    void replace_withAWeakETag_isPreconditionFailed() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(3)));

        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().toInput(), "W/\"3\"")))
                .expectError(PreconditionFailedException.class)
                .verify();
    }

    @Test
    void replace_ofAnUnknownId_isCatalogEntryNotFound() {
        when(port.findById("nobody")).thenReturn(Mono.empty());

        StepVerifier.create(inTenant(service.replace("nobody", doctorIdConfiguration().toInput(), "\"0\"")))
                .expectError(CatalogEntryNotFoundException.class)
                .verify();
    }

    @Test
    void replace_whenSomeoneChangedItBetweenReadAndWrite_isPreconditionFailed() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(3)));
        when(port.updateIfVersion(any(), eq(3L))).thenReturn(Mono.just(Optional.empty()));

        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().toInput(), "\"3\"")))
                .expectError(PreconditionFailedException.class)
                .verify();

        verify(tenantCredentialProfileService, never()).invalidateCache(any());
    }

    @Test
    void replace_whenItWasDeletedBetweenReadAndWrite_isCatalogEntryNotFound() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(3))).thenReturn(Mono.empty());
        when(port.updateIfVersion(any(), eq(3L))).thenReturn(Mono.just(Optional.empty()));

        StepVerifier.create(inTenant(service.replace(DOCTORID, doctorIdConfiguration().toInput(), "\"3\"")))
                .expectError(CatalogEntryNotFoundException.class)
                .verify();
    }

    @Test
    void replace_withAnInvalidConfiguration_isRejectedWithoutWriting() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(3)));

        StepVerifier.create(inTenant(service.replace(DOCTORID,
                        doctorIdConfiguration().withIdentifiers(List.of(identifier("dni", "nationalId"))).toInput(), "\"3\"")))
                .expectErrorSatisfies(e -> assertThat(((CatalogConfigurationException) e).code())
                        .isEqualTo("field_not_in_schema"))
                .verify();

        verify(port, never()).updateIfVersion(any(), anyLong());
    }

    /** A replacement is always complete, so there is nothing to answer 404 for after writing: it is refused before. */
    @Test
    void replace_ofARowWhoseTypeFileIsNotLoaded_isUnknownSchemaWithoutWriting() {
        CatalogEntry orphan = new CatalogEntry("retired.type.sd.1", null, false, null, null, null, List.of(), 0,
                Instant.now(), Instant.now());
        when(port.findById("retired.type.sd.1")).thenReturn(Mono.just(orphan));

        StepVerifier.create(inTenant(service.replace("retired.type.sd.1", doctorIdConfiguration().toInput(), "\"0\"")))
                .expectError(UnknownSchemaException.class)
                .verify();

        verify(port, never()).updateIfVersion(any(), anyLong());
    }

    // ---- setEnabled ------------------------------------------------------------

    @Test
    void setEnabled_disabling_updatesAndDropsTheCache() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(1)));
        when(port.updateIfVersion(any(), eq(1L))).thenAnswer(inv ->
                Mono.just(Optional.of(stored(inv.getArgument(0), 2))));

        StepVerifier.create(inTenant(service.setEnabled(DOCTORID, false, "\"1\"")))
                .assertNext(entry -> {
                    assertThat(entry.enabled()).isFalse();
                    assertThat(entry.version()).isEqualTo(2);
                })
                .verifyComplete();

        verify(tenantCredentialProfileService).invalidateCache(TENANT);
    }

    @Test
    void setEnabled_auditsDisablingAndEnablingAsTheirOwnActions() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(1)));
        when(port.updateIfVersion(any(), eq(1L))).thenAnswer(inv ->
                Mono.just(Optional.of(stored(inv.getArgument(0), 2))));
        StepVerifier.create(inTenant(service.setEnabled(DOCTORID, false, "\"1\""))).expectNextCount(1).verifyComplete();

        CatalogEntry disabled = filledDoctorId(2).withEnabled(false);
        when(port.findById(DOCTORID)).thenReturn(Mono.just(disabled));
        when(port.updateIfVersion(any(), eq(2L))).thenAnswer(inv ->
                Mono.just(Optional.of(stored(inv.getArgument(0), 3))));
        StepVerifier.create(inTenant(service.setEnabled(DOCTORID, true, "\"2\""))).expectNextCount(1).verifyComplete();

        ArgumentCaptor<CatalogEntryChange> change = ArgumentCaptor.forClass(CatalogEntryChange.class);
        verify(changeAuditor, times(2)).audit(change.capture());
        assertThat(change.getAllValues()).extracting(CatalogEntryChange::action)
                .containsExactly(CatalogEntryChange.Action.DISABLE, CatalogEntryChange.Action.ENABLE);
        assertThat(change.getAllValues().get(0).changes()).containsOnlyKeys("enabled");
        assertThat(change.getAllValues().get(0).changes().get("enabled")).containsExactly(true, false);
        assertThat(change.getAllValues().get(1).changes().get("enabled")).containsExactly(false, true);
    }

    @Test
    void setEnabled_whenRejected_auditsNothing() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(7)));

        StepVerifier.create(inTenant(service.setEnabled(DOCTORID, false, "\"6\"")))
                .expectError(PreconditionFailedException.class)
                .verify();

        verify(changeAuditor, never()).audit(any());
    }

    @Test
    void setEnabled_enablingAnEntrySavedWithoutDeliveryModes_isNoDeliveryMode() {
        CatalogEntry withoutModes = new CatalogEntry(DOCTORID, DOCTORID_URI, false, Set.of(),
                new CatalogEntry.Validity(365, false, null), null, List.of(), 5, Instant.now(), Instant.now());
        when(port.findById(DOCTORID)).thenReturn(Mono.just(withoutModes));

        StepVerifier.create(inTenant(service.setEnabled(DOCTORID, true, "\"5\"")))
                .expectErrorSatisfies(e -> assertThat(((CatalogConfigurationException) e).code())
                        .isEqualTo("no_delivery_mode"))
                .verify();

        verify(port, never()).updateIfVersion(any(), anyLong());
    }

    @Test
    void setEnabled_enablingARowNotConfiguredYet_completesItInTheSameWrite() {
        CatalogEntry seeded = new CatalogEntry(DOCTORID, null, false, null, null, null, List.of(), 0,
                Instant.now(), Instant.now());
        when(port.findById(DOCTORID)).thenReturn(Mono.just(seeded));
        when(port.updateIfVersion(any(), eq(0L))).thenAnswer(inv ->
                Mono.just(Optional.of(stored(inv.getArgument(0), 1))));

        StepVerifier.create(inTenant(service.setEnabled(DOCTORID, true, "\"0\"")))
                .assertNext(entry -> {
                    assertThat(entry.enabled()).isTrue();
                    assertThat(entry.isFilled()).isTrue();
                })
                .verifyComplete();
    }

    /** Its credential type file is gone, so the filler cannot complete it: 404 as for get, and nothing is written. */
    @Test
    void setEnabled_ofARowWhoseTypeFileIsNotLoaded_isCatalogEntryNotFoundWithoutWriting() {
        CatalogEntry orphan = new CatalogEntry("retired.type.sd.1", null, false, null, null, null, List.of(), 0,
                Instant.now(), Instant.now());
        when(port.findById("retired.type.sd.1")).thenReturn(Mono.just(orphan));

        StepVerifier.create(inTenant(service.setEnabled("retired.type.sd.1", true, "\"0\"")))
                .expectError(CatalogEntryNotFoundException.class)
                .verify();
        StepVerifier.create(inTenant(service.setEnabled("retired.type.sd.1", false, "\"0\"")))
                .expectError(CatalogEntryNotFoundException.class)
                .verify();

        verify(port, never()).updateIfVersion(any(), anyLong());
        verify(tenantCredentialProfileService, never()).invalidateCache(any());
    }

    @Test
    void setEnabled_disablingAFilledRowWhoseTypeFileIsNotLoaded_stillWrites() {
        CatalogEntry retired = filled("retired.type.sd.1", null, 4);
        when(port.findById("retired.type.sd.1")).thenReturn(Mono.just(retired));
        when(port.updateIfVersion(any(), eq(4L))).thenAnswer(inv ->
                Mono.just(Optional.of(stored(inv.getArgument(0), 5))));

        StepVerifier.create(inTenant(service.setEnabled("retired.type.sd.1", false, "\"4\"")))
                .assertNext(entry -> assertThat(entry.enabled()).isFalse())
                .verifyComplete();
    }

    @Test
    void setEnabled_withoutIfMatch_isPreconditionRequired() {
        StepVerifier.create(inTenant(service.setEnabled(DOCTORID, false, null)))
                .expectError(PreconditionRequiredException.class)
                .verify();
    }

    @Test
    void setEnabled_withIfMatchAny_isPreconditionRequired() {
        StepVerifier.create(inTenant(service.setEnabled(DOCTORID, false, "*")))
                .expectError(PreconditionRequiredException.class)
                .verify();
    }

    @Test
    void setEnabled_withAnOldETag_isPreconditionFailed() {
        when(port.findById(DOCTORID)).thenReturn(Mono.just(filledDoctorId(7)));

        StepVerifier.create(inTenant(service.setEnabled(DOCTORID, false, "\"6\"")))
                .expectError(PreconditionFailedException.class)
                .verify();
    }

    @Test
    void setEnabled_ofAnUnknownId_isCatalogEntryNotFound() {
        when(port.findById("nobody")).thenReturn(Mono.empty());

        StepVerifier.create(inTenant(service.setEnabled("nobody", true, "\"0\"")))
                .expectError(CatalogEntryNotFoundException.class)
                .verify();
    }

    // ---- tenant ----------------------------------------------------------------

    @Test
    void everyOperation_withoutTenantInTheContext_isTenantNotResolved() {
        StepVerifier.create(service.list(null)).expectError(TenantNotResolvedException.class).verify();
        StepVerifier.create(service.get(DOCTORID)).expectError(TenantNotResolvedException.class).verify();
        StepVerifier.create(service.create(createDoctorId())).expectError(TenantNotResolvedException.class).verify();
        StepVerifier.create(service.replace(DOCTORID, doctorIdConfiguration().toInput(), "\"0\""))
                .expectError(TenantNotResolvedException.class).verify();
        StepVerifier.create(service.setEnabled(DOCTORID, true, "\"0\""))
                .expectError(TenantNotResolvedException.class).verify();

        verifyNoInteractions(port);
    }

    // ---- helpers ---------------------------------------------------------------

    private static Context tenant() {
        return Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT);
    }

    private static <T> Mono<T> inTenant(Mono<T> mono) {
        return mono.contextWrite(tenant());
    }

    private static CreateCatalogEntryCommand createDoctorId() {
        return new CreateCatalogEntryCommand(DOCTORID_URI, doctorIdConfiguration().toInput());
    }

    private static CatalogEntry stored(CatalogEntry entry, long version) {
        return new CatalogEntry(entry.credentialConfigurationId(), entry.schemaUri(), entry.enabled(),
                entry.deliveryModes(), entry.validity(), entry.subject(), entry.searchIdentifiers(), version,
                Instant.now(), Instant.now());
    }

    private static CatalogEntry filledDoctorId(long version) {
        return filled(DOCTORID, DOCTORID_URI, version);
    }

    private static CatalogEntry filled(String credentialConfigurationId, String schemaUri, long version) {
        return new CatalogEntry(credentialConfigurationId, schemaUri, true,
                Set.of(DeliveryMode.EMAIL, DeliveryMode.UI), new CatalogEntry.Validity(36500, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("givenName")), " "), List.of(), version,
                Instant.now(), Instant.now());
    }

    private static SearchIdentifierInput identifier(String name, String... path) {
        return new SearchIdentifierInput(name, List.of(path), null);
    }

    /** The DoctorID v1 example of the contract. */
    private static Configuration doctorIdConfiguration() {
        return new Configuration(true, new SubjectInput(List.of(List.of("givenName"), List.of("familyName")), " ", null),
                List.of(identifier("colegiado", "personal_administrative_number")));
    }

    private record Configuration(boolean enabled, SubjectInput subject, List<SearchIdentifierInput> identifiers) {

        Configuration withEnabled(boolean value) {
            return new Configuration(value, subject, identifiers);
        }

        Configuration withSubject(SubjectInput value) {
            return new Configuration(enabled, value, identifiers);
        }

        Configuration withIdentifiers(List<SearchIdentifierInput> value) {
            return new Configuration(enabled, subject, value);
        }

        CatalogConfigurationInput toInput() {
            return new CatalogConfigurationInput(enabled, List.of("email", "ui"),
                    new ValidityInput(36500, false, null, null), subject, identifiers, null);
        }
    }
}
