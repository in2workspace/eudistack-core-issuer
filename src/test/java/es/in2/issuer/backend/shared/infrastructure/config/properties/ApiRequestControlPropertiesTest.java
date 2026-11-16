package es.in2.issuer.backend.shared.infrastructure.config.properties;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.RequesterKind;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitPolicy;
import es.in2.issuer.backend.shared.infrastructure.config.ApiRequestControlConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.PropertySourcesPlaceholdersResolver;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the volume limits and the idempotency times of the order (EUD-269) as the issuer starts with them: the
 * {@code application.yml} it ships, bound and turned into the policy as in production, and the defaults of the
 * properties themselves. The integration tests raise or lower every limit, so without this a change of 300 to 30,
 * of 60 to 600 or of the retention would keep the pipeline green. The numbers are the ones AC-08 and AC-20 of the
 * issuance PRD, AC-09 of the revocation PRD and AC-10 of the query PRD cite (FR-08 and FR-09 of EUD-254, FR-07 of
 * EUD-247, §5 of EUD-255).
 */
class ApiRequestControlPropertiesTest {

    private static ApiRequestControlProperties shipped() throws IOException {
        List<PropertySource<?>> documents = new YamlPropertySourceLoader()
                .load("application.yml", new ClassPathResource("application.yml"));
        MutablePropertySources sources = new MutablePropertySources();
        documents.forEach(sources::addLast);
        // Placeholders resolve to their defaults: only the file is read, never the environment of the machine.
        return new Binder(ConfigurationPropertySources.from(sources), new PropertySourcesPlaceholdersResolver(sources))
                .bind("issuer.api", ApiRequestControlProperties.class)
                .get();
    }

    private static void assertTheLimitsOfTheOrder(VolumeLimitPolicy policy) {
        assertThat(policy.window().length()).isEqualTo(Duration.ofMinutes(1));
        for (ApiOperation operation : List.of(ApiOperation.ISSUANCE, ApiOperation.REVOCATION, ApiOperation.READ)) {
            assertThat(policy.of(operation).of(RequesterKind.SYSTEM)).as(operation + " systems").isEqualTo(300);
            assertThat(policy.of(operation).of(RequesterKind.PERSON)).as(operation + " person").isEqualTo(30);
        }
        assertThat(policy.of(ApiOperation.SEARCH).of(RequesterKind.SYSTEM)).as("search systems").isEqualTo(60);
        assertThat(policy.of(ApiOperation.SEARCH).of(RequesterKind.PERSON)).as("search person").isEqualTo(10);
    }

    @Test
    void theShippedConfiguration_hasTheVolumeLimitsOfTheOrder() throws IOException {
        assertTheLimitsOfTheOrder(new ApiRequestControlConfig().volumeLimitPolicy(shipped()));
    }

    @Test
    void theShippedConfiguration_keepsTheIdempotencyKeys24Hours_withALeaseOf2Minutes() throws IOException {
        ApiRequestControlProperties.Idempotency idempotency = shipped().getIdempotency();

        assertThat(idempotency.getRetention()).isEqualTo(Duration.ofHours(24));
        assertThat(idempotency.getLease()).isEqualTo(Duration.ofMinutes(2));
    }

    @Test
    void theDefaultsOfTheProperties_areTheSameValues() {
        ApiRequestControlProperties defaults = new ApiRequestControlProperties();

        assertTheLimitsOfTheOrder(new ApiRequestControlConfig().volumeLimitPolicy(defaults));
        assertThat(defaults.getIdempotency().getRetention()).isEqualTo(Duration.ofHours(24));
        assertThat(defaults.getIdempotency().getLease()).isEqualTo(Duration.ofMinutes(2));
    }
}
