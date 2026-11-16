package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * The volume limits of the management APIs (EUD-269): per operation, how many requests a person may
 * send and how many the systems of an organization may send together in one window. Support can raise
 * the limit of the systems of one organization from the tenant configuration (FR-09 of EUD-254).
 *
 * @param window the window every limit is counted in
 * @param limits the limits of each operation; every operation must have one
 */
public record VolumeLimitPolicy(SlidingWindow window, Map<ApiOperation, Limits> limits) {

    /**
     * @param systemsPerOrganization requests the systems of one organization may send together
     * @param perPerson              requests one person may send
     */
    public record Limits(int systemsPerOrganization, int perPerson) {
        public Limits {
            if (systemsPerOrganization < 1 || perPerson < 1) {
                throw new IllegalArgumentException("A volume limit must be at least 1");
            }
        }

        public int of(RequesterKind kind) {
            return kind == RequesterKind.SYSTEM ? systemsPerOrganization : perPerson;
        }
    }

    public VolumeLimitPolicy {
        Objects.requireNonNull(window, "window");
        Objects.requireNonNull(limits, "limits");
        Map<ApiOperation, Limits> copy = new EnumMap<>(ApiOperation.class);
        copy.putAll(limits);
        for (ApiOperation operation : ApiOperation.values()) {
            if (!copy.containsKey(operation)) {
                throw new IllegalArgumentException("No volume limit for " + operation.key());
            }
        }
        limits = Map.copyOf(copy);
    }

    public Limits of(ApiOperation operation) {
        return limits.get(operation);
    }
}
