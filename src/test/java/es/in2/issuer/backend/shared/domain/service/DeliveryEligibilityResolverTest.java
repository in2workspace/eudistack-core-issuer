package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeliveryEligibilityResolverTest {

    private static final String CONFIG_ID = "learcredential.employee.w3c.4";

    @Mock
    private TenantDeliveryConfigService tenantDeliveryConfigService;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @InjectMocks
    private DeliveryEligibilityResolver resolver;

    private static CredentialProfile profile(boolean cnfRequired) {
        return CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(cnfRequired)
                .build();
    }

    @Nested
    class GetEligibleModes {

        @Test
        void getEligibleModes_configExplicit_returnsConfiguredSetVerbatim() {
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.EMAIL)));

            StepVerifier.create(resolver.getEligibleModes(CONFIG_ID))
                    .assertNext(modes -> assertEquals(Set.of(DeliveryMode.EMAIL), modes))
                    .verifyComplete();
        }

        @Test
        void getEligibleModes_configAbsentAndCnfNotRequired_defaultsToAllModes() {
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID)).thenReturn(Mono.empty());
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile(false));

            StepVerifier.create(resolver.getEligibleModes(CONFIG_ID))
                    .assertNext(modes -> assertEquals(EnumSet.allOf(DeliveryMode.class), modes))
                    .verifyComplete();
        }

        @Test
        void getEligibleModes_configAbsentAndCnfRequired_defaultExcludesDirect() {
            // Mirrors IssuanceWorkflowImpl#resolveAndValidateDeliveryModes' own default (EUD-167),
            // so the admin view never shows a mode as eligible that issuance would reject.
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID)).thenReturn(Mono.empty());
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile(true));

            StepVerifier.create(resolver.getEligibleModes(CONFIG_ID))
                    .assertNext(modes -> assertEquals(Set.of(DeliveryMode.EMAIL, DeliveryMode.UI), modes))
                    .verifyComplete();
        }

        @Test
        void getEligibleModes_configuredSetIncludesDirectEvenWhenCnfRequired_returnedAsIs() {
            // EC-04: config persists what the admin set verbatim; the cnfRequired hard rule is
            // enforced at issuance time (IssuanceWorkflowImpl), not filtered out of this query.
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.DIRECT)));

            StepVerifier.create(resolver.getEligibleModes(CONFIG_ID))
                    .assertNext(modes -> assertEquals(Set.of(DeliveryMode.DIRECT), modes))
                    .verifyComplete();
        }

        @Test
        void getEligibleModes_repositoryFails_propagatesErrorInsteadOfDefault() {
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID))
                    .thenReturn(Mono.error(new RuntimeException("db unavailable")));

            StepVerifier.create(resolver.getEligibleModes(CONFIG_ID))
                    .expectError(RuntimeException.class)
                    .verify();
        }
    }
}
