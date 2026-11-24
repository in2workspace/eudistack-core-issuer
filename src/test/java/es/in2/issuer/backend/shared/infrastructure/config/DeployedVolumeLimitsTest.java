package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The volume limits that are deployed (application.yml has no placeholder for them, so every environment gets these):
 * the ones of the API convention, rules 11 and 12, that EUD-255 AC-11 and NFR-3 ask for. ApiVolumeLimitHttpIT runs the
 * search with these values; this test keeps them from drifting apart.
 */
class DeployedVolumeLimitsTest {

    private static final String PREFIX = "issuer.api.volume-limit.";

    @Test
    void theQueryLimits_areTheOnesOfTheApiConvention() {
        Properties deployed = deployed();

        assertThat(deployed.getProperty(PREFIX + "window")).isEqualTo("1m");
        assertThat(deployed.getProperty(PREFIX + "read.per-person")).isEqualTo("30");
        assertThat(deployed.getProperty(PREFIX + "read.systems-per-organization")).isEqualTo("300");
        assertThat(deployed.getProperty(PREFIX + "search.per-person"))
                .isEqualTo(String.valueOf(ApiVolumeLimitHttpIT.SEARCHES_PER_PERSON));
        assertThat(deployed.getProperty(PREFIX + "search.systems-per-organization"))
                .isEqualTo(String.valueOf(ApiVolumeLimitHttpIT.SEARCHES_PER_ORGANIZATION_SYSTEMS));
    }

    private static Properties deployed() {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application.yml"));
        return yaml.getObject();
    }
}
