package es.in2.issuer.backend.shared.domain.policy.service.impl;

import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.JWTClaimMissingException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireOrganizationRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequirePowerRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireTenantMatchRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireValidStatusRule;
import es.in2.issuer.backend.shared.domain.policy.service.StatusListPdpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.PLATFORM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListPdpServiceImpl implements StatusListPdpService {

    private final PolicyContextFactory policyContextFactory;

    @Override
    public Mono<Void> validateRevokeCredential(String processId,
                                               String token,
                                               Issuance issuance) {

        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            log.info("Process ID: {} - Validating 'revoke' action...", processId);
            return new RequireValidStatusRule().evaluate(null, issuance.getCredentialStatus())
                    .then(Mono.defer(() -> policyContextFactory.fromTokenSimple(token, tenantDomain)))
                    .flatMap(ctx -> new RequireTenantMatchRule().evaluate(ctx, null).thenReturn(ctx))
                    .flatMap(ctx ->
                            RequirePowerRule.<Void>of("Onboarding", "Execute")
                                    .evaluate(ctx, null)
                                    .then(new RequireOrganizationRule()
                                            .evaluate(ctx, issuance.getOrganizationIdentifier()))
                    );
        });
    }

    @Override
    public Mono<Void> validateRevokePermission(String processId, String token) {
        return authorizedContext(processId, token).then();
    }

    @Override
    public Mono<Void> validateRevokeScope(String processId, String token, Issuance issuance) {
        return authorizedContext(processId, token)
                .flatMap(ctx -> new RequireOrganizationRule().evaluate(ctx, issuance.getOrganizationIdentifier()))
                .onErrorMap(UnauthorizedRoleException.class, e -> {
                    log.info("Process ID: {} - Revocation denied: process out of the caller's scope", processId);
                    return new IssuanceNotFoundException("No issuance found for the given id");
                });
    }

    /**
     * Tenant and power, the checks that do not depend on the process. A token this decision cannot
     * read, or that names no organization, is an invalid token rather than an unexpected error.
     */
    private Mono<PolicyContext> authorizedContext(String processId, String token) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            log.info("Process ID: {} - Validating 'revoke' permission...", processId);
            return policyContextFactory.fromTokenSimple(token, tenantDomain)
                    .onErrorMap(StatusListPdpServiceImpl::isUnusableToken,
                            e -> new InvalidTokenException("The access token cannot be used to decide a revocation"))
                    .flatMap(ctx -> ctx.organizationIdentifier() == null
                            ? Mono.<PolicyContext>error(new InvalidTokenException("The access token names no organization"))
                            : Mono.just(ctx))
                    .flatMap(ctx -> new RequireTenantMatchRule().evaluate(ctx, null).thenReturn(ctx))
                    .flatMap(StatusListPdpServiceImpl::requireWritableTenant)
                    .flatMap(ctx -> RequirePowerRule.<Void>of("Onboarding", "Execute").evaluate(ctx, null)
                            .onErrorMap(UnauthorizedRoleException.class,
                                    e -> new InsufficientPermissionException(e.getMessage()))
                            .thenReturn(ctx));
        });
    }

    private static boolean isUnusableToken(Throwable error) {
        return error instanceof JWTClaimMissingException
                || error instanceof JWTParsingException
                || error instanceof InvalidCredentialFormatException;
    }

    /** A SysAdmin on the platform tenant has a read-only view: a revocation is irreversible. */
    private static Mono<PolicyContext> requireWritableTenant(PolicyContext ctx) {
        if (ctx.sysAdmin() && PLATFORM_TENANT.equals(ctx.tenantDomain())) {
            return Mono.error(new InsufficientPermissionException("Read-only access from platform tenant"));
        }
        return Mono.just(ctx);
    }

    @Override
    public Mono<Void> validateRevokeCredentialSystem(String processId, Issuance issuance) {
        return Mono.defer(() -> {
            log.info("Process ID: {} - Validating 'revoke' action (system)...", processId);
            return new RequireValidStatusRule().evaluate(null, issuance.getCredentialStatus());
        });
    }
}
