package es.in2.issuer.backend.shared.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.exception.TenantSecretKeyUnavailableException;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LocalTenantSecretKeyAdapterTest {

    private static final String SEED = "local-seed-of-at-least-thirty-two-chars";

    @Test
    void keyOf_derivesA32ByteKeyPerTenant_theSameEveryTime() {
        LocalTenantSecretKeyAdapter adapter = new LocalTenantSecretKeyAdapter(SEED);

        byte[] sandbox = adapter.keyOf("sandbox").block();
        byte[] cgcom = adapter.keyOf("cgcom").block();

        assertThat(sandbox).hasSize(32).isEqualTo(new LocalTenantSecretKeyAdapter(SEED).keyOf("sandbox").block());
        assertThat(cgcom).hasSize(32).isNotEqualTo(sandbox);
        assertThat(new LocalTenantSecretKeyAdapter(SEED + "x").keyOf("sandbox").block()).isNotEqualTo(sandbox);
    }

    @Test
    void keyOf_withoutTenant_isUnavailable() {
        StepVerifier.create(new LocalTenantSecretKeyAdapter(SEED).keyOf(" "))
                .verifyError(TenantSecretKeyUnavailableException.class);
    }

    @Test
    void aSeedShorterThan32Characters_isRefused() {
        assertThatThrownBy(() -> new LocalTenantSecretKeyAdapter("short")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new LocalTenantSecretKeyAdapter(null)).isInstanceOf(IllegalStateException.class);
    }
}
