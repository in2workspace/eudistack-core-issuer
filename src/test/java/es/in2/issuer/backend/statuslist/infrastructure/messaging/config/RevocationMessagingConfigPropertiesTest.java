package es.in2.issuer.backend.statuslist.infrastructure.messaging.config;

import es.in2.issuer.backend.statuslist.domain.model.RevocationTenantBinding;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.config.RevocationMessagingConfig.RevocationMessagingProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AD-8: {@code tenant-binding}'s format is validated fail-fast at startup (via the record's
 * compact constructor, which Spring invokes at {@code @ConfigurationProperties} binding time).
 * Its existence in {@code tenant_registry} is a separate, process-time concern (EC-07),
 * exercised in {@code RevocationInstructionSingleTenantIT}, not here.
 */
class RevocationMessagingConfigPropertiesTest {

    @Test
    void construct_tenantBindingAbsent_succeeds() {
        RevocationMessagingProperties properties = new RevocationMessagingProperties(false, null);

        assertThat(properties.toRevocationTenantBinding()).isEqualTo(RevocationTenantBinding.none());
    }

    @Test
    void construct_tenantBindingBlank_succeeds() {
        RevocationMessagingProperties properties = new RevocationMessagingProperties(false, "   ");

        assertThat(properties.toRevocationTenantBinding()).isEqualTo(RevocationTenantBinding.none());
    }

    @Test
    void construct_tenantBindingValidFormat_succeeds() {
        RevocationMessagingProperties properties = new RevocationMessagingProperties(true, "prh");

        assertThat(properties.toRevocationTenantBinding()).isEqualTo(RevocationTenantBinding.of("prh"));
    }

    @Test
    void construct_tenantBindingInvalidFormat_failsFast() {
        assertThatThrownBy(() -> new RevocationMessagingProperties(true, "prh!invalid"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("tenant-binding");
    }

    @Test
    void construct_tenantBindingWithWhitespace_failsFast() {
        assertThatThrownBy(() -> new RevocationMessagingProperties(true, "prh tenant"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
