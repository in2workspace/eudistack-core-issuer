package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialMachineFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PolicyContextFactoryTest {

    private static final String ADMIN_ORG_ID = "ADMIN_ORG";
    private static final String TOKEN = "test-token";

    @Mock
    private JWTService jwtService;

    @Mock
    private AppConfig appConfig;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @Mock
    private LEARCredentialMachineFactory learCredentialMachineFactory;

    @Mock
    private LabelCredentialFactory labelCredentialFactory;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    private PolicyContextFactory factory;

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = new ObjectMapper();
        CredentialFactory credentialFactory = new CredentialFactory(
                learCredentialEmployeeFactory,
                learCredentialMachineFactory,
                labelCredentialFactory,
                credentialProcedureService,
                deferredCredentialMetadataService
        );
        factory = new PolicyContextFactory(
                jwtService, objectMapper, appConfig, learCredentialEmployeeFactory, credentialFactory
        );
    }

    // --- fromTokenSimple ---

    @Test
    void fromTokenSimple_createsContextWithPowers() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        String vcJson = "{\"type\":[\"LEARCredentialEmployee\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        LEARCredentialEmployee credential = buildLEARCredentialEmployee("ORG-123");
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcJson)).thenReturn(credential);
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.organizationIdentifier()).isEqualTo("ORG-123");
                    assertThat(ctx.credentialType()).isEqualTo(LEAR_CREDENTIAL_EMPLOYEE);
                    assertThat(ctx.sysAdmin()).isFalse();
                    assertThat(ctx.powers()).hasSize(1);
                    assertThat(ctx.tenantDomain()).isEqualTo("DOME");
                })
                .verifyComplete();
    }

    @Test
    void fromTokenSimple_setsIsSysAdminWhenOrgMatchesAdminOrgAndHasOnboardingPower() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        String vcJson = "{\"type\":[\"LEARCredentialEmployee\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        LEARCredentialEmployee credential = buildLEARCredentialEmployee(ADMIN_ORG_ID);
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcJson)).thenReturn(credential);
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.sysAdmin()).isTrue();
                    assertThat(ctx.organizationIdentifier()).isEqualTo(ADMIN_ORG_ID);
                })
                .verifyComplete();
    }

    @Test
    void fromTokenSimple_notSysAdminWhenAdminOrgButNoOnboardingPower() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        String vcJson = "{\"type\":[\"LEARCredentialEmployee\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        LEARCredentialEmployee credential = buildLEARCredentialEmployeeWithPower(
                ADMIN_ORG_ID, "ProductOffering", "Execute");
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcJson)).thenReturn(credential);
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.sysAdmin()).isFalse();
                    assertThat(ctx.organizationIdentifier()).isEqualTo(ADMIN_ORG_ID);
                })
                .verifyComplete();
    }

    // --- fromTokenForIssuance ---

    @Test
    void fromTokenForIssuance_createsContextWithPowers() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        String vcJson = "{\"type\":[\"LEARCredentialEmployee\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        LEARCredentialEmployee credential = buildLEARCredentialEmployee("ORG-123");
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(vcJson)).thenReturn(credential);
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, LEAR_CREDENTIAL_EMPLOYEE, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.credentialType()).isEqualTo(LEAR_CREDENTIAL_EMPLOYEE);
                    assertThat(ctx.tenantDomain()).isEqualTo("DOME");
                })
                .verifyComplete();
    }

    @Test
    void fromTokenForIssuance_failsWhenCredentialTypeNotAllowedForLabelCredential() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        // VC contains LEARCredentialEmployee but LABEL_CREDENTIAL requires LEARCredentialMachine
        String vcJson = "{\"type\":[\"LEARCredentialEmployee\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, LABEL_CREDENTIAL, "DOME"))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("LEARCredentialMachine"))
                .verify();
    }

    @Test
    void fromTokenForIssuance_failsWhenVcTypeMissing() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        // VC without type field
        String vcJson = "{\"id\":\"something\"}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, LEAR_CREDENTIAL_EMPLOYEE, "DOME"))
                .expectError(InsufficientPermissionException.class)
                .verify();
    }

    // --- Helper ---

    private LEARCredentialEmployee buildLEARCredentialEmployee(String orgId) {
        return buildLEARCredentialEmployeeWithPower(orgId, "Onboarding", "Execute");
    }

    private LEARCredentialEmployee buildLEARCredentialEmployeeWithPower(
            String orgId, String function, String action) {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier(orgId)
                .build();
        Power power = Power.builder()
                .function(function)
                .action(action)
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:123")
                        .firstName("John")
                        .lastName("Doe")
                        .email("john@example.com")
                        .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();
        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }
}
