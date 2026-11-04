package es.in2.issuer.backend.shared.domain.model.port;

import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix;

/**
 * Source of the issuer action matrix. Implementations return the rules in force at the time of
 * the call, so a change to the configuration applies to the next request without a restart (FR-15).
 */
public interface AuthorizationMatrixProvider {

    AuthorizationMatrix current();
}
