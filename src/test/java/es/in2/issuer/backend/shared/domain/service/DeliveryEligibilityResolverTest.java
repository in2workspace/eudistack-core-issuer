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
        void getEligibleModes_configAbsent_defaultsToAllModes() {
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID)).thenReturn(Mono.empty());

            StepVerifier.create(resolver.getEligibleModes(CONFIG_ID))
                    .assertNext(modes -> assertEquals(EnumSet.allOf(DeliveryMode.class), modes))
                    .verifyComplete();
        }

        @Test
        void getEligibleModes_configuredSetIncludesDirectEvenWhenCnfRequired_returnedAsIs() {
            // EC-04: config persists what the admin set; the cnfRequired rule only
            // narrows the *effective* eligibility check (isEligible), not this query.
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

    @Nested
    class IsEligible {

        @Test
        void isEligible_requestedModeWithinConfigured_returnsTrue() {
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile(false));
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI)));

            StepVerifier.create(resolver.isEligible(CONFIG_ID, Set.of(DeliveryMode.EMAIL)))
                    .expectNext(true)
                    .verifyComplete();
        }

        @Test
        void isEligible_requestedModeNotConfigured_returnsFalse() {
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile(false));
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.EMAIL)));

            StepVerifier.create(resolver.isEligible(CONFIG_ID, Set.of(DeliveryMode.DIRECT)))
                    .expectNext(false)
                    .verifyComplete();
        }

        @Test
        void isEligible_cnfRequiredExcludesDirect_evenWhenPersistedAsConfigured() {
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile(true));
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL)));

            StepVerifier.create(resolver.isEligible(CONFIG_ID, Set.of(DeliveryMode.DIRECT)))
                    .expectNext(false)
                    .verifyComplete();
        }

        @Test
        void isEligible_cnfRequiredButNonDirectModeRequested_returnsTrue() {
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile(true));
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL)));

            StepVerifier.create(resolver.isEligible(CONFIG_ID, Set.of(DeliveryMode.EMAIL)))
                    .expectNext(true)
                    .verifyComplete();
        }

        @Test
        void isEligible_noExplicitConfigAndCnfNotRequired_defaultsPermissive() {
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile(false));
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID)).thenReturn(Mono.empty());

            StepVerifier.create(resolver.isEligible(CONFIG_ID, Set.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL)))
                    .expectNext(true)
                    .verifyComplete();
        }

        @Test
        void isEligible_noExplicitConfigAndCnfRequired_stillExcludesDirectByDefault() {
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile(true));
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID)).thenReturn(Mono.empty());

            StepVerifier.create(resolver.isEligible(CONFIG_ID, Set.of(DeliveryMode.DIRECT)))
                    .expectNext(false)
                    .verifyComplete();
        }

        @Test
        void isEligible_repositoryFails_failsClosedInsteadOfDefaultingToEligible() {
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile(false));
            when(tenantDeliveryConfigService.getEligibleModes(CONFIG_ID))
                    .thenReturn(Mono.error(new RuntimeException("db unavailable")));

            StepVerifier.create(resolver.isEligible(CONFIG_ID, Set.of(DeliveryMode.EMAIL)))
                    .expectError(RuntimeException.class)
                    .verify();
        }
    }
}
