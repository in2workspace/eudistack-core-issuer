package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Issuer action matrix (EUD-253 prd.md, Annex A): the user types, how each one is recognized by
 * its powers, and the scope every user type has on every action. Read as configuration by
 * {@link es.in2.issuer.backend.shared.domain.model.port.AuthorizationMatrixProvider}, so a rule
 * change applies without redeploying (FR-15).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthorizationMatrix(
        @JsonProperty("version") int version,
        @JsonProperty("user_types") Map<String, UserTypeRule> userTypes,
        @JsonProperty("recognition_order") List<String> recognitionOrder,
        @JsonProperty("actions") List<ActionRule> actions
) {

    /** Placeholder in a power's domain that stands for the request's tenant. */
    public static final String TENANT_PLACEHOLDER = "{tenant}";

    public ActionRule action(String actionId) {
        return actions.stream()
                .filter(a -> a.id().equals(actionId))
                .findFirst()
                .orElse(null);
    }

    /**
     * Fails if the matrix is not usable: every user type of the recognition order is defined and
     * every action states the scope of every user type, so a missing entry never reads as "allowed".
     */
    public AuthorizationMatrix validate() {
        if (userTypes == null || userTypes.isEmpty() || recognitionOrder == null || recognitionOrder.isEmpty()
                || actions == null || actions.isEmpty()) {
            throw new IllegalStateException("Authorization matrix must define user_types, recognition_order and actions");
        }
        for (String type : recognitionOrder) {
            if (!userTypes.containsKey(type)) {
                throw new IllegalStateException("recognition_order references unknown user type: " + type);
            }
        }
        for (ActionRule action : actions) {
            if (action.id() == null || action.scope() == null) {
                throw new IllegalStateException("Every action needs an id and a scope");
            }
            for (String type : recognitionOrder) {
                if (action.scope().get(type) == null) {
                    throw new IllegalStateException("Action " + action.id() + " has no scope for user type " + type);
                }
            }
        }
        return this;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserTypeRule(
            @JsonProperty("name") String name,
            @JsonProperty("recognized_by") List<PowerPattern> recognizedBy,
            @JsonProperty("acts_as") String actsAs,
            @JsonProperty("platform_tenant") String platformTenant,
            @JsonProperty("security_trace") boolean securityTrace
    ) {
        public static final String READ_ONLY = "read_only";

        public List<PowerPattern> recognizedByOrEmpty() {
            return recognizedBy != null ? recognizedBy : List.of();
        }

        public boolean readOnlyInPlatformTenant() {
            return READ_ONLY.equals(platformTenant);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ActionRule(
            @JsonProperty("id") String id,
            @JsonProperty("name") String name,
            @JsonProperty("writes") boolean writes,
            @JsonProperty("grants") PowerPattern grants,
            @JsonProperty("grants_outside_tenant") boolean grantsOutsideTenant,
            @JsonProperty("requires_power") PowerPattern requiresPower,
            @JsonProperty("credential_types") List<String> credentialTypes,
            @JsonProperty("scope") Map<String, Scope> scope
    ) {
        public List<String> credentialTypesOrEmpty() {
            return credentialTypes != null ? credentialTypes : List.of();
        }
    }

    /**
     * One power as the matrix writes it. {@code type}, {@code function} and {@code action} are
     * compared exactly -- the type is always lowercase and a variant is not recognized (§5, point 13);
     * the domain is an identifier and is compared ignoring case.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PowerPattern(
            @JsonProperty("type") String type,
            @JsonProperty("domain") String domain,
            @JsonProperty("function") String function,
            @JsonProperty("action") String action
    ) {

        public String resolvedDomain(String tenant) {
            return TENANT_PLACEHOLDER.equals(domain) ? tenant : domain;
        }

        /** Whether a power held by the caller satisfies this pattern in the given tenant. */
        public boolean isHeldBy(Power power, String tenant) {
            return power != null
                    && Objects.equals(type, power.type())
                    && Objects.equals(function, power.function())
                    && domainMatches(power.domain(), tenant)
                    && hasAction(power, action);
        }

        /**
         * Whether a power being granted in an attestation is this one. Unlike {@link #isHeldBy}, the
         * type is compared ignoring case: a granted {@code Domain} is not a valid power, but it must not
         * slip past the check of who may grant it.
         */
        public boolean isGrantedBy(Power power, String tenant) {
            return power != null
                    && type != null && type.equalsIgnoreCase(power.type())
                    && Objects.equals(function, power.function())
                    && domainMatches(power.domain(), tenant)
                    && hasAction(power, action);
        }

        private boolean domainMatches(String powerDomain, String tenant) {
            String expected = resolvedDomain(tenant);
            return expected != null && expected.equalsIgnoreCase(powerDomain);
        }

        public static boolean hasAction(Power power, String action) {
            if (power.action() instanceof List<?> actions) {
                return actions.stream().anyMatch(a -> action.equals(String.valueOf(a)));
            }
            return power.action() != null && action.equals(power.action().toString());
        }

        @Override
        public String toString() {
            return type + " · " + domain + " · " + function + " · " + action;
        }
    }

    public enum Scope {
        ANY_ORGANIZATION("any_organization"),
        OWN_ORGANIZATION("own_organization"),
        DENY("deny"),
        ALLOW("allow");

        private final String value;

        Scope(String value) {
            this.value = value;
        }

        @JsonValue
        public String value() {
            return value;
        }

        @JsonCreator
        public static Scope fromValue(String value) {
            for (Scope s : values()) {
                if (s.value.equals(value)) {
                    return s;
                }
            }
            throw new IllegalArgumentException("Unknown scope: " + value);
        }
    }
}
