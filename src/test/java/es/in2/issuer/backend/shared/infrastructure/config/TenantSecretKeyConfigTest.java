package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
import es.in2.issuer.backend.shared.infrastructure.adapter.LocalTenantSecretKeyAdapter;
import es.in2.issuer.backend.shared.infrastructure.adapter.SsmTenantSecretKeyAdapter;
import es.in2.issuer.backend.shared.infrastructure.config.properties.SearchIdentifierProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.annotation.UserConfigurations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/** The tenant key source by profile, and what each one refuses at startup (EUD-267, SEC-17). */
class TenantSecretKeyConfigTest {

    @Configuration
    @EnableConfigurationProperties(SearchIdentifierProperties.class)
    static class Properties {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(UserConfigurations.of(Properties.class, TenantSecretKeyConfig.class));

    @Test
    void outsideTheLocalProfile_theKeysComeFromParameterStore() {
        runner.withPropertyValues("issuer.search-identifiers.key-parameter=/eudistack/dev/config/tenants/{tenant}/issuer/k")
                .run(context -> assertThat(context.getBean(TenantSecretKeyPort.class))
                        .isInstanceOf(SsmTenantSecretKeyAdapter.class));
    }

    @Test
    void outsideTheLocalProfile_withoutAParameter_theIssuerStillStarts() {
        runner.run(context -> assertThat(context).hasNotFailed()
                .getBean(TenantSecretKeyPort.class).isInstanceOf(SsmTenantSecretKeyAdapter.class));
    }

    @Test
    void outsideTheLocalProfile_aLocalSeed_isRefusedAtStartup() {
        runner.withPropertyValues("issuer.search-identifiers.local-key-seed=local-seed-of-at-least-thirty-two-chars")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void aParameterNameWithoutTheTenantPlaceholder_isRefusedAtStartup() {
        runner.withPropertyValues("issuer.search-identifiers.key-parameter=/eudistack/dev/one-key-for-all")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void withTheLocalProfile_theKeysAreDerivedFromTheSeed() {
        runner.withInitializer(context -> context.getEnvironment().setActiveProfiles("local"))
                .withPropertyValues("issuer.search-identifiers.local-key-seed=local-seed-of-at-least-thirty-two-chars")
                .run(context -> assertThat(context.getBean(TenantSecretKeyPort.class))
                        .isInstanceOf(LocalTenantSecretKeyAdapter.class));
    }

    @Test
    void withTheLocalProfile_withoutASeed_theIssuerDoesNotStart() {
        runner.withInitializer(context -> context.getEnvironment().setActiveProfiles("local"))
                .run(context -> assertThat(context).hasFailed());
    }
}
