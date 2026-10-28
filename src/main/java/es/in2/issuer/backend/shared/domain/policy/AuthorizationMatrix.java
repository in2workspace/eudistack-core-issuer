package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Issuer action matrix (EUD-253 prd.md, Annex A): the user types, how each one is recognized by
 * its powers, and the scope every user type has on every action. Read as configuration by
 * {@link es.in2.issuer.backend.shared.domain.model.port.AuthorizationMatrixProvider}, so a rule
 * change applies without redeploying (FR-15).
 *
 * <p>Unknown keys are not ignored: the matrix is a security policy, and a misspelt key
 * ({@code recognised_by}, {@code require_power}) silently read as "absent" would open what it was
 * meant to restrict. The reader fails on them, and {@link #validate} rejects every omission that
 * would read as "allowed".
 */
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
     * Domains that are never a tenant's own: the literal domains user types are recognized by (the
     * platform's {@code EUDISTACK}). A power of one of them is outside every tenant, even one that
     * happened to be named the same.
     */
    public boolean isPlatformDomain(String domain) {
        return domain != null && userTypes.values().stream()
                .flatMap(rule -> rule.recognizedByOrEmpty().stream())
                .map(PowerPattern::domain)
                .anyMatch(d -> !TENANT_PLACEHOLDER.equals(d) && d.equalsIgnoreCase(domain));
    }

    /**
     * Fails if the matrix is not usable, so a missing or misspelt entry never reads as "allowed":
     * <ul>
     *   <li>the user types the issuer knows are all in the recognition order;</li>
     *   <li>every user type of the recognition order is defined, and only the last one -- the
     *       catch-all for an attestation without powers -- is recognized by no power;</li>
     *   <li>every power pattern states its type, domain, function and action;</li>
     *   <li>every action has a unique id, states whether it writes, and gives the scope of every
     *       user type;</li>
     *   <li>the actions the issuer decides exist, and one rule covers powers outside the tenant.</li>
     * </ul>
     *
     * @param requiredActionIds the action ids the issuer decides with this matrix
     */
    public AuthorizationMatrix validate(Collection<String> requiredActionIds) {
        require(userTypes != null && !userTypes.isEmpty() && recognitionOrder != null && !recognitionOrder.isEmpty()
                && actions != null && !actions.isEmpty(),
                "Authorization matrix must define user_types, recognition_order and actions");
        validateUserTypes();
        Set<String> ids = new HashSet<>();
        for (ActionRule action : actions) {
            validateAction(action);
            require(ids.add(action.id()), "Duplicated action id: " + action.id());
        }
        for (String required : requiredActionIds) {
            require(ids.contains(required), "Authorization matrix has no rule for action " + required);
        }
        require(actions.stream().anyMatch(ActionRule::grantsOutsideTenant),
                "Authorization matrix needs a rule for granting powers outside the tenant (grants_outside_tenant)");
        return this;
    }

    private void validateUserTypes() {
        for (String known : List.of(RecognizedCaller.PLATFORM_ADMIN, RecognizedCaller.TENANT_ADMIN,
                RecognizedCaller.ORGANIZATION_ADMIN, RecognizedCaller.USER)) {
            // A renamed type would silently demote its holders to USER in every role-based path.
            require(recognitionOrder.contains(known), "recognition_order must include the user type " + known);
        }
        for (int i = 0; i < recognitionOrder.size(); i++) {
            String type = recognitionOrder.get(i);
            UserTypeRule rule = userTypes.get(type);
            require(rule != null, "recognition_order references unknown user type: " + type);
            boolean last = i == recognitionOrder.size() - 1;
            if (last) {
                require(rule.recognizedByOrEmpty().isEmpty(),
                        "The last user type of recognition_order must be the catch-all (no recognized_by): " + type);
            } else {
                require(!rule.recognizedByOrEmpty().isEmpty(),
                        "User type " + type + " is recognized by no power; only the last one may be");
            }
            rule.recognizedByOrEmpty().forEach(pattern -> pattern.validate("recognized_by of " + type));
        }
    }

    private void validateAction(ActionRule action) {
        require(action.id() != null && action.scope() != null && action.writes() != null,
                "Every action needs an id, writes and a scope");
        for (String type : recognitionOrder) {
            require(action.scope().get(type) != null, "Action " + action.id() + " has no scope for user type " + type);
        }
        Stream.of(action.grants(), action.requiresPower())
                .filter(Objects::nonNull)
                .forEach(pattern -> pattern.validate("action " + action.id()));
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

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

    /** {@code writes} is a {@link Boolean} so its absence fails validation instead of reading as "does not write". */
    public record ActionRule(
            @JsonProperty("id") String id,
            @JsonProperty("name") String name,
            @JsonProperty("writes") Boolean writes,
            @JsonProperty("grants") PowerPattern grants,
            @JsonProperty("grants_outside_tenant") boolean grantsOutsideTenant,
            @JsonProperty("requires_power") PowerPattern requiresPower,
            @JsonProperty("credential_types") List<String> credentialTypes,
            @JsonProperty("scope") Map<String, Scope> scope
    ) {
        public List<String> credentialTypesOrEmpty() {
            return credentialTypes != null ? credentialTypes : List.of();
        }

        public boolean isWrite() {
            return Boolean.TRUE.equals(writes);
        }
    }

    /**
     * One power as the matrix writes it. {@code type}, {@code function} and {@code action} are
     * compared exactly -- the type is always lowercase and a variant is not recognized (§5, point 13);
     * the domain is an identifier and is compared ignoring case.
     */
    public record PowerPattern(
            @JsonProperty("type") String type,
            @JsonProperty("domain") String domain,
            @JsonProperty("function") String function,
            @JsonProperty("action") String action
    ) {

        void validate(String where) {
            require(type != null && domain != null && function != null && action != null,
                    "Incomplete power pattern in " + where + ": type, domain, function and action are required");
        }

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
