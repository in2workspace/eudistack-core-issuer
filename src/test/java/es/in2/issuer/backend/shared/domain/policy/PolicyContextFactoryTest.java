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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;
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

    private PolicyContextFactory factory;

    @BeforeEach
    void setUp() {
        factory = new PolicyContextFactory(
                jwtService, objectMapper, appConfig, credentialParser
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

        ObjectNode vcNode = objectMapper.createObjectNode();
        CredentialProfile profile = mock(CredentialProfile.class);
        Power power = Power.builder().function("Onboarding").action("Execute").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(vcNode, profile, LEAR_CREDENTIAL_EMPLOYEE);
        when(credentialParser.parse(vcJson)).thenReturn(parsed);
        when(credentialParser.extractPowers(vcNode, profile)).thenReturn(List.of(power));
        when(credentialParser.extractOrganizationId(vcNode, profile)).thenReturn("ORG-123");
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

        ObjectNode vcNode = objectMapper.createObjectNode();
        CredentialProfile profile = mock(CredentialProfile.class);
        Power power = Power.builder().function("Onboarding").action("Execute").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(vcNode, profile, LEAR_CREDENTIAL_EMPLOYEE);
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

        String vcJson = "{\"type\":[\"LEARCredentialEmployee\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        ObjectNode vcNode = objectMapper.createObjectNode();
        CredentialProfile profile = mock(CredentialProfile.class);
        Power power = Power.builder().function("ProductOffering").action("Execute").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(vcNode, profile, LEAR_CREDENTIAL_EMPLOYEE);
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

        String vcJson = "{\"type\":[\"LEARCredentialEmployee\"]}";
        when(jwtService.getClaimFromPayload(payload, "vc")).thenReturn(vcJson);

        ObjectNode vcNode = objectMapper.createObjectNode();
        CredentialProfile profile = mock(CredentialProfile.class);
        Power power = Power.builder().function("Onboarding").action("Execute").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(vcNode, profile, LEAR_CREDENTIAL_EMPLOYEE);
        when(credentialParser.parse(vcJson)).thenReturn(parsed);
        when(credentialParser.extractPowers(vcNode, profile)).thenReturn(List.of(power));
        when(credentialParser.extractOrganizationId(vcNode, profile)).thenReturn("ORG-123");
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
}
