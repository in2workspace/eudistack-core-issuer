package es.in2.issuer.backend.shared.domain.policy.service;

import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import reactor.core.publisher.Mono;

/**
 * Policy decision point for writes to the tenant's attestation catalog (EUD-266, D15).
 */
public interface CatalogPdpService {

    /**
     * Authorizes a catalog write. Emits the caller's {@link AuthorizationContext} when allowed;
     * fails with {@code InsufficientPermissionException} when the caller is not the tenant's
     * administrator (or a SysAdmin able to write), or with {@code TenantMismatchException} when
     * the token belongs to another tenant. Both denials are audited.
     *
     * <p>Meant to run before the request body is read: {@code pdp.authorizeWrite(header).then(body)}.
     * The tenant is taken from the Reactor context.
     */
    Mono<AuthorizationContext> authorizeWrite(String authorizationHeader);
}
