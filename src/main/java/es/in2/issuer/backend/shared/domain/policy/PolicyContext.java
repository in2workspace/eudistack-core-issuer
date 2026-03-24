package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;

import java.util.List;

/**
 * Pre-parsed authorization context from a JWT access token.
 * Created once per request by PolicyContextFactory.
 */
public record PolicyContext(
        String organizationIdentifier,
        List<Power> powers,
        JsonNode credential,
        CredentialProfile profile,
        String credentialType,
        boolean sysAdmin,
        String tenantDomain,
        String tokenTenant
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
     * Checks if the user has a power matching the required function, action, and domain.
     */
    public boolean hasPowerWithDomain(String function, String action, String domain) {
        return powers.stream().anyMatch(p ->
                function.equals(p.function())
                        && hasAction(p, action)
                        && domain.equals(p.domain())
        );
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
