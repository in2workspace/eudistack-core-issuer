package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PolicyContextFactoryTest {

    private static final String ADMIN_ORG_ID = "ADMIN_ORG";
    private static final String TOKEN = "test-token";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private JWTService jwtService;

    @Mock
    private IssuerProperties appConfig;

    @Mock
    private DynamicCredentialParser credentialParser;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    private PolicyContextFactory factory;

    @BeforeEach
    void setUp() {
        factory = new PolicyContextFactory(
                jwtService, objectMapper, appConfig, credentialParser, credentialProfileRegistry
        );
    }

    // --- fromTokenSimple ---

    @Test
    void fromTokenSimple_createsContextWithPowers() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        String vcJson = "{\"type\":[\"learcredential.employee.w3c.4\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        ObjectNode vcNode = objectMapper.createObjectNode();
        CredentialProfile profile = mock(CredentialProfile.class);
        Power power = Power.builder().function("Onboarding").action("Execute").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(vcNode, profile, "learcredential.employee.w3c.4");
        when(credentialParser.parse(vcJson)).thenReturn(parsed);
        when(credentialParser.extractPowers(vcNode, profile)).thenReturn(List.of(power));
        when(credentialParser.extractOrganizationId(vcNode, profile)).thenReturn("ORG-123");
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.organizationIdentifier()).isEqualTo("ORG-123");
                    assertThat(ctx.credentialType()).isEqualTo("learcredential.employee.w3c.4");
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

        String vcJson = "{\"type\":[\"learcredential.employee.w3c.4\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        ObjectNode vcNode = objectMapper.createObjectNode();
        CredentialProfile profile = mock(CredentialProfile.class);
        Power power = Power.builder().function("Onboarding").action("Execute").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(vcNode, profile, "learcredential.employee.w3c.4");
        when(credentialParser.parse(vcJson)).thenReturn(parsed);
        when(credentialParser.extractPowers(vcNode, profile)).thenReturn(List.of(power));
        when(credentialParser.extractOrganizationId(vcNode, profile)).thenReturn(ADMIN_ORG_ID);
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

        String vcJson = "{\"type\":[\"learcredential.employee.w3c.4\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        ObjectNode vcNode = objectMapper.createObjectNode();
        CredentialProfile profile = mock(CredentialProfile.class);
        Power power = Power.builder().function("ProductOffering").action("Execute").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(vcNode, profile, "learcredential.employee.w3c.4");
        when(credentialParser.parse(vcJson)).thenReturn(parsed);
        when(credentialParser.extractPowers(vcNode, profile)).thenReturn(List.of(power));
        when(credentialParser.extractOrganizationId(vcNode, profile)).thenReturn(ADMIN_ORG_ID);
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

        String vcJson = "{\"type\":[\"learcredential.employee.w3c.4\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        ObjectNode vcNode = objectMapper.createObjectNode();
        CredentialProfile profile = mock(CredentialProfile.class);
        Power power = Power.builder().function("Onboarding").action("Execute").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(vcNode, profile, "learcredential.employee.w3c.4");
        when(credentialParser.parse(vcJson)).thenReturn(parsed);
        when(credentialParser.extractPowers(vcNode, profile)).thenReturn(List.of(power));
        when(credentialParser.extractOrganizationId(vcNode, profile)).thenReturn("ORG-123");
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, "learcredential.employee.w3c.4", "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.credentialType()).isEqualTo("learcredential.employee.w3c.4");
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

        // VC contains learcredential.employee.w3c.4 but "gx.labelcredential.w3c.1" requires learcredential.machine.w3c.3
        String vcJson = "{\"type\":[\"learcredential.employee.w3c.4\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        // Mock the registry to return a profile requiring learcredential.machine.w3c.3
        CredentialProfile labelProfile = CredentialProfile.builder()
                .credentialConfigurationId("gx.labelcredential.w3c.1")
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .requiredEmitterConfigIds(List.of("learcredential.machine.w3c.3"))
                        .build())
                .build();
        when(credentialProfileRegistry.getByConfigurationId("gx.labelcredential.w3c.1")).thenReturn(labelProfile);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, "gx.labelcredential.w3c.1", "DOME"))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("learcredential.machine.w3c.3"))
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

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, "learcredential.employee.w3c.4", "DOME"))
                .expectError(InsufficientPermissionException.class)
                .verify();
    }
}
