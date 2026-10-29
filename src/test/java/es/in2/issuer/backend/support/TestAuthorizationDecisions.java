package es.in2.issuer.backend.support;

import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.RecognizedCaller;

import java.util.List;

/** Builds the permitted C1 decision the PDP returns for each role, for tests below the decision point. */
public final class TestAuthorizationDecisions {

    private TestAuthorizationDecisions() {
    }

    public static AuthorizationDecision query(String organizationIdentifier, UserRole role, boolean readOnly) {
        String userType = switch (role) {
            case SYSADMIN -> RecognizedCaller.PLATFORM_ADMIN;
            case TENANT_ADMIN -> RecognizedCaller.TENANT_ADMIN;
            case LEAR -> RecognizedCaller.ORGANIZATION_ADMIN;
            case USER -> RecognizedCaller.USER;
        };
        AuthorizationMatrix.Scope scope = role == UserRole.LEAR
                ? AuthorizationMatrix.Scope.OWN_ORGANIZATION : AuthorizationMatrix.Scope.ANY_ORGANIZATION;
        Caller caller = new Caller(organizationIdentifier, List.of(), "sandbox", null, null);
        RecognizedCaller recognized = new RecognizedCaller(caller, readOnly ? "platform" : "sandbox", userType,
                role == UserRole.SYSADMIN ? RecognizedCaller.TENANT_ADMIN : userType, readOnly, role == UserRole.SYSADMIN);
        return new AuthorizationDecision("C1", recognized, scope);
    }
}
