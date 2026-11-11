package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The small value types of the idempotency and the volume limits (EUD-269). */
class RequestControlModelTest {

    @Test
    void requester_systemsOfAnOrganizationShareTheirCount_personsDoNot() {
        assertThat(Requester.system("ORG-1").countingScope()).isEqualTo(Requester.system("ORG-1").countingScope());
        assertThat(Requester.person("ORG-1", "p1").countingScope())
                .isNotEqualTo(Requester.person("ORG-1", "p2").countingScope())
                .isNotEqualTo(Requester.system("ORG-1").countingScope());
        assertThat(Requester.person("ORG-1", "p1").countingScope())
                .isNotEqualTo(Requester.person("ORG-2", "p1").countingScope());
    }

    @Test
    void requester_aPersonNeedsAKey_aSystemDropsIt() {
        assertThatThrownBy(() -> Requester.person("ORG-1", " ")).isInstanceOf(IllegalArgumentException.class);
        assertThat(new Requester("ORG-1", RequesterKind.SYSTEM, "ignored").personKey()).isNull();
    }

    @Test
    void volumeLimitPolicy_needsALimitForEveryOperation() {
        SlidingWindow window = new SlidingWindow(Duration.ofMinutes(1));
        VolumeLimitPolicy.Limits limits = new VolumeLimitPolicy.Limits(300, 30);

        assertThatThrownBy(() -> new VolumeLimitPolicy(window, Map.of(ApiOperation.ISSUANCE, limits)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new VolumeLimitPolicy.Limits(0, 30)).isInstanceOf(IllegalArgumentException.class);
        assertThat(limits.of(RequesterKind.SYSTEM)).isEqualTo(300);
        assertThat(limits.of(RequesterKind.PERSON)).isEqualTo(30);
    }

    @Test
    void idempotencyPolicy_leaseCannotOutliveTheRetention() {
        assertThatThrownBy(() -> new IdempotencyPolicy(Duration.ofMinutes(1), Duration.ofMinutes(2)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new IdempotencyPolicy(Duration.ZERO, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void storedResponse_onlySuccessful_comparesItsBody_neverPrintsIt() {
        StoredResponse response = new StoredResponse(201, "application/json", "/api/v1/issuances/1", "{\"a\":1}".getBytes());

        assertThatThrownBy(() -> new StoredResponse(500, null, null, null)).isInstanceOf(IllegalArgumentException.class);
        assertThat(response).isEqualTo(new StoredResponse(201, "application/json", "/api/v1/issuances/1", "{\"a\":1}".getBytes()))
                .hasSameHashCodeAs(new StoredResponse(201, "application/json", "/api/v1/issuances/1", "{\"a\":1}".getBytes()));
        assertThat(response.toString()).doesNotContain("{\"a\":1}").contains("bodyBytes=7");
        assertThat(new StoredResponse(204, null, null, null).body()).isEmpty();
    }
}
