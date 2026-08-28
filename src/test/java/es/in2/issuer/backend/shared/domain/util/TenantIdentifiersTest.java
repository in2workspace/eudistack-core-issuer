package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TenantIdentifiersTest {

    @Test
    void stripEnvSuffix_null_returnsNull() {
        assertThat(TenantIdentifiers.stripEnvSuffix(null)).isNull();
    }

    @Test
    void stripEnvSuffix_stgSuffix_stripped() {
        assertThat(TenantIdentifiers.stripEnvSuffix("cgcom-stg")).isEqualTo("cgcom");
    }

    @Test
    void stripEnvSuffix_devSuffix_stripped() {
        assertThat(TenantIdentifiers.stripEnvSuffix("sandbox-dev")).isEqualTo("sandbox");
    }

    @Test
    void stripEnvSuffix_preSuffix_stripped() {
        assertThat(TenantIdentifiers.stripEnvSuffix("kpmg-pre")).isEqualTo("kpmg");
    }

    @Test
    void stripEnvSuffix_noSuffix_unchanged() {
        assertThat(TenantIdentifiers.stripEnvSuffix("cgcom")).isEqualTo("cgcom");
    }

    @Test
    void stripEnvSuffix_unrelatedHyphenatedSuffix_unchanged() {
        assertThat(TenantIdentifiers.stripEnvSuffix("acme-corp")).isEqualTo("acme-corp");
    }
}
