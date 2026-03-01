package es.in2.issuer.backend.shared.domain.policy;

import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.LEARCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;

import java.util.List;

/**
 * Pre-parsed authorization context from a JWT access token.
 * Created once per request by PolicyContextFactory.
 */
public record PolicyContext(
        String role,
        String organizationIdentifier,
        List<Power> powers,
        LEARCredential credential,
        String credentialType,
        boolean sysAdmin
) {

    /**
     * Checks if the user has a specific power function with a specific action.
     */
    public boolean hasPower(String function, String action) {
        return powers.stream().anyMatch(p ->
                function.equals(p.function()) && hasAction(p, action)
        );
    }

    /**
     * Checks if the user has any power with the given function and action (separate anyMatch calls).
     * This preserves the original behavior where function and action were checked independently.
     */
    public boolean hasPowerFunctionAndAction(String function, String action) {
        return powers.stream().anyMatch(p -> function.equals(p.function()))
                && powers.stream().anyMatch(p -> hasAction(p, action));
    }

    /**
     * Checks if all powers in a list match a specific function.
     */
    public static boolean allPowersMatchFunction(List<Power> powers, String function) {
        return powers.stream().allMatch(p -> function.equals(p.function()));
    }

    /**
     * Checks if a power contains a specific action.
     */
    public static boolean hasAction(Power power, String action) {
        if (power.action() instanceof List<?> actions) {
            return actions.stream().anyMatch(a -> action.equals(a.toString()));
        }
        return action.equals(power.action().toString());
    }
}
