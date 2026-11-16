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
        assertThat(Requester.system("t", "ORG-1", "m1").countingScope())
                .isEqualTo(Requester.system("t", "ORG-1", "m2").countingScope());
        assertThat(Requester.person("t", "ORG-1", "p1").countingScope())
                .isNotEqualTo(Requester.person("t", "ORG-1", "p2").countingScope())
                .isNotEqualTo(Requester.system("t", "ORG-1", "m1").countingScope());
        assertThat(Requester.person("t", "ORG-1", "p1").countingScope())
                .isNotEqualTo(Requester.person("t", "ORG-2", "p1").countingScope());
    }

    @Test
    void requester_theTenantSeparatesTheCountsAndTheIdempotencyKeys() {
        assertThat(Requester.person("a", "ORG-1", "p1").countingScope())
                .isNotEqualTo(Requester.person("b", "ORG-1", "p1").countingScope());
        assertThat(Requester.person("a", "ORG-1", "p1").idempotencyScope())
                .isNotEqualTo(Requester.person("b", "ORG-1", "p1").idempotencyScope());
        assertThatThrownBy(() -> Requester.person(" ", "ORG-1", "p1")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requester_theSystemsOfAnOrganizationShareTheCount_butNotTheIdempotencyKeys() {
        Requester first = Requester.system("t", "ORG-1", "m1");
        Requester second = Requester.system("t", "ORG-1", "m2");

        assertThat(first.countingScope()).isEqualTo(second.countingScope());
        assertThat(first.idempotencyScope()).isPresent().isNotEqualTo(second.idempotencyScope());
        assertThat(Requester.person("t", "ORG-1", "m1").idempotencyScope()).isNotEqualTo(first.idempotencyScope());
    }

    @Test
    void requester_aCallerTheTokenDoesNotName_hasNoIdempotencyScope_butIsCounted() {
        Requester person = Requester.person("t", "ORG-1", " ");
        Requester system = Requester.system("t", "ORG-1", null);

        assertThat(person.callerKey()).isNull();
        assertThat(person.idempotencyScope()).isEmpty();
        assertThat(system.idempotencyScope()).isEmpty();
        assertThat(person.countingScope()).isEqualTo(Requester.person("t", "ORG-1", null).countingScope())
                .isNotEqualTo(Requester.person("t", "ORG-1", "p1").countingScope());
        assertThat(system.countingScope()).isEqualTo(Requester.system("t", "ORG-1", "m1").countingScope());
    }

    @Test
    void idempotencyPolicy_renewsTwicePerLease() {
        IdempotencyPolicy policy = new IdempotencyPolicy(Duration.ofHours(24), Duration.ofMinutes(2));

        assertThat(policy.renewEvery()).isEqualTo(Duration.ofMinutes(1));
    }

    @Test
    void secrets_deriveOneKeyPerPurposeAndSecret_neverPrintTheSecret() {
        RequestControlSecrets.Secret one = RequestControlSecrets.Secret.of(1, "a".repeat(32));
        RequestControlSecrets.Secret two = RequestControlSecrets.Secret.of(2, "b".repeat(32));

        assertThat(one.derive("x")).hasSize(32).isEqualTo(one.derive("x")).isNotEqualTo(one.derive("y"))
                .isNotEqualTo(two.derive("x"));
        assertThat(one.mac("x", "input")).hasSize(64).isNotEqualTo(one.mac("y", "input"));
        assertThat(one.toString()).doesNotContain("aaaa").contains("redacted");
        assertThat(one).isEqualTo(RequestControlSecrets.Secret.of(1, "a".repeat(32)))
                .hasSameHashCodeAs(RequestControlSecrets.Secret.of(1, "a".repeat(32)));
    }

    @Test
    void secrets_rejectShortSecretsIdsOutOfRangeAndTwoSecretsWithOneId() {
        RequestControlSecrets.Secret one = RequestControlSecrets.Secret.of(1, "a".repeat(32));
        RequestControlSecrets.Secret sameId = RequestControlSecrets.Secret.of(1, "b".repeat(32));
        RequestControlSecrets.Secret two = RequestControlSecrets.Secret.of(2, "b".repeat(32));
        String longEnough = "a".repeat(32);

        assertThatThrownBy(() -> RequestControlSecrets.Secret.of(1, "short")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RequestControlSecrets.Secret.of(0, longEnough)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RequestControlSecrets.Secret.of(256, longEnough)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RequestControlSecrets(one, sameId)).isInstanceOf(IllegalArgumentException.class);
        RequestControlSecrets rotating = new RequestControlSecrets(two, one);
        assertThat(rotating.byId(1)).contains(one);
        assertThat(rotating.byId(2)).contains(two);
        assertThat(rotating.byId(3)).isEmpty();
        assertThat(new RequestControlSecrets(one).previousSecret()).isEmpty();
    }

    @Test
    void volumeLimitPolicy_needsALimitForEveryOperation() {
        SlidingWindow window = new SlidingWindow(Duration.ofMinutes(1));
        VolumeLimitPolicy.Limits limits = new VolumeLimitPolicy.Limits(300, 30);

        Map<ApiOperation, VolumeLimitPolicy.Limits> onlyIssuance = Map.of(ApiOperation.ISSUANCE, limits);

        assertThatThrownBy(() -> new VolumeLimitPolicy(window, onlyIssuance))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new VolumeLimitPolicy.Limits(0, 30)).isInstanceOf(IllegalArgumentException.class);
        assertThat(limits.of(RequesterKind.SYSTEM)).isEqualTo(300);
        assertThat(limits.of(RequesterKind.PERSON)).isEqualTo(30);
    }

    @Test
    void idempotencyPolicy_leaseCannotOutliveTheRetention() {
        Duration oneMinute = Duration.ofMinutes(1);
        Duration twoMinutes = Duration.ofMinutes(2);

        assertThatThrownBy(() -> new IdempotencyPolicy(oneMinute, twoMinutes))
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
