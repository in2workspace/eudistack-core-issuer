package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.JWTService;
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
    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.1";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private JWTService jwtService;

    @Mock
    private IssuerProperties appConfig;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    private PolicyContextFactory factory;

    @BeforeEach
    void setUp() {
        factory = new PolicyContextFactory(
                jwtService, objectMapper, appConfig, credentialProfileRegistry
        );
    }

    private void setupFlatTokenClaims(Payload payload, String credentialType, String orgId) {
        // credential_type claim: getClaimFromPayload serializes strings with quotes
        when(jwtService.getClaimFromPayload(payload, "credential_type"))
                .thenReturn("\"" + credentialType + "\"");

        // power claim: JSON array
        String powerJson = "[{\"function\":\"Onboarding\",\"action\":\"Execute\",\"domain\":\"DOME\",\"type\":\"Domain\"}]";
        when(jwtService.getClaimFromPayload(payload, "power")).thenReturn(powerJson);

        // mandator claim: JSON object
        String mandatorJson = "{\"organizationIdentifier\":\"" + orgId + "\",\"organization\":\"Test Org\"}";
        when(jwtService.getClaimFromPayload(payload, "mandator")).thenReturn(mandatorJson);
    }

    private CredentialProfile buildProfile(String configId) {
        return CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .policyExtraction(CredentialProfile.PolicyExtraction.builder()
                        .powersPath("power")
                        .mandatorPath("mandator")
                        .orgIdField("organizationIdentifier")
                        .build())
                .build();
    }

    // --- fromTokenSimple ---

    @Test
    void fromTokenSimple_createsContextWithPowers() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        setupFlatTokenClaims(payload, CREDENTIAL_TYPE, "ORG-123");

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.organizationIdentifier()).isEqualTo("ORG-123");
                    assertThat(ctx.credentialType()).isEqualTo(CREDENTIAL_TYPE);
                    assertThat(ctx.sysAdmin()).isFalse();
                    assertThat(ctx.powers()).hasSize(1);
                    assertThat(ctx.powers().getFirst().function()).isEqualTo("Onboarding");
                    assertThat(ctx.tenantDomain()).isEqualTo("DOME");
                    assertThat(ctx.profile()).isEqualTo(profile);
                    assertThat(ctx.credential()).isNotNull();
                })
                .verifyComplete();
    }

    @Test
    void fromTokenSimple_setsIsSysAdminWhenOrgMatchesAdminOrgAndHasOnboardingPower() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        setupFlatTokenClaims(payload, CREDENTIAL_TYPE, ADMIN_ORG_ID);

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);
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

        // credential_type
        when(jwtService.getClaimFromPayload(payload, "credential_type"))
                .thenReturn("\"" + CREDENTIAL_TYPE + "\"");

        // power with non-Onboarding function
        String powerJson = "[{\"function\":\"ProductOffering\",\"action\":\"Execute\",\"domain\":\"DOME\",\"type\":\"Domain\"}]";
        when(jwtService.getClaimFromPayload(payload, "power")).thenReturn(powerJson);

        // mandator
        String mandatorJson = "{\"organizationIdentifier\":\"" + ADMIN_ORG_ID + "\",\"organization\":\"Test Org\"}";
        when(jwtService.getClaimFromPayload(payload, "mandator")).thenReturn(mandatorJson);

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);
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

        setupFlatTokenClaims(payload, CREDENTIAL_TYPE, "ORG-123");

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(profile);
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, CREDENTIAL_TYPE, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.credentialType()).isEqualTo(CREDENTIAL_TYPE);
                    assertThat(ctx.tenantDomain()).isEqualTo("DOME");
                    assertThat(ctx.powers()).hasSize(1);
                })
                .verifyComplete();
    }

    @Test
    void fromTokenForIssuance_failsWhenCredentialTypeNotAllowedForLabelCredential() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        // Emitter has learcredential.employee.w3c.1
        when(jwtService.getClaimFromPayload(payload, "credential_type"))
                .thenReturn("\"" + CREDENTIAL_TYPE + "\"");

        // Target profile requires learcredential.machine.w3c.1
        CredentialProfile labelProfile = CredentialProfile.builder()
                .credentialConfigurationId("gx.labelcredential.w3c.1")
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .requiredEmitterConfigIds(List.of("learcredential.machine.w3c.1"))
                        .build())
                .build();
        when(credentialProfileRegistry.getByConfigurationId("gx.labelcredential.w3c.1")).thenReturn(labelProfile);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, "gx.labelcredential.w3c.1", "DOME"))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("learcredential.machine.w3c.1"))
                .verify();
    }

    @Test
    void fromTokenForIssuance_succeedsWhenEmitterTypeMatchesRequiredConfigId() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        String machineType = "learcredential.machine.w3c.1";
        setupFlatTokenClaims(payload, machineType, "ORG-456");

        // Target profile requires learcredential.machine.w3c.1 and emitter has it
        CredentialProfile labelProfile = CredentialProfile.builder()
                .credentialConfigurationId("gx.labelcredential.w3c.1")
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .requiredEmitterConfigIds(List.of(machineType))
                        .build())
                .build();
        when(credentialProfileRegistry.getByConfigurationId("gx.labelcredential.w3c.1")).thenReturn(labelProfile);

        CredentialProfile machineProfile = buildProfile(machineType);
        when(credentialProfileRegistry.getByConfigurationId(machineType)).thenReturn(machineProfile);
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, "gx.labelcredential.w3c.1", "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.credentialType()).isEqualTo(machineType);
                    assertThat(ctx.organizationIdentifier()).isEqualTo("ORG-456");
                })
                .verifyComplete();
    }

    @Test
    void fromTokenForIssuance_acceptsAnyTypeWhenNoIssuancePolicy() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        setupFlatTokenClaims(payload, CREDENTIAL_TYPE, "ORG-789");

        // Target profile without issuance policy
        CredentialProfile targetProfile = CredentialProfile.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .build();
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(targetProfile);

        CredentialProfile emitterProfile = buildProfile(CREDENTIAL_TYPE);
        // getByConfigurationId is called twice: once for checkIfEmitterIsAllowedToIssue, once for resolveProfile
        // Since both use the same key, one stub covers both
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(emitterProfile);
        when(appConfig.getAdminOrganizationId()).thenReturn(ADMIN_ORG_ID);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, CREDENTIAL_TYPE, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.credentialType()).isEqualTo(CREDENTIAL_TYPE);
                })
                .verifyComplete();
    }
}
