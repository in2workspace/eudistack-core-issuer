package es.in2.issuer.backend.issuance.application.workflow.impl;

import es.in2.issuer.backend.issuance.application.workflow.CredentialOfferRenewalWorkflow;
import es.in2.issuer.backend.issuance.domain.exception.OfferNotRenewableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalDeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalInvalidIssuanceIdException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalIssuanceNotFoundException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalPermissionDeniedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalTenantMismatchException;
import es.in2.issuer.backend.issuance.domain.model.CredentialOfferRenewal;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.exception.JWTClaimMissingException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireTenantMatchRule;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.AUTHORIZATION_CODE;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Checks run in the order of the acceptance contract (EUD-295 ac.md): tenant of the token, id
 * format, permission (decided before loading the issuance, so who may not issue gets 403 whether
 * or not the issuance exists), existence and scope, and last status and delivery mode.
 * Authentication and the volume limit are decided earlier by the web filters.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferRenewalWorkflowImpl implements CredentialOfferRenewalWorkflow {

    private static final String FN_ONBOARDING = "Onboarding";
    private static final String ACT_EXECUTE = "Execute";
    private static final String FN_CERTIFICATION = "Certification";
    private static final String ACT_ATTEST = "Attest";
    private static final String BASIS_PLATFORM_ADMIN = "platform_admin";

    // Audit events (conv-quality-security-gates §3.4, ENS op.exp.8), named like the revocation's.
    static final String EVENT_PERMITTED = "credential.offer.renew.permitted";
    static final String EVENT_DENIED = "credential.offer.renew.denied";
    static final String EVENT_RENEWED = "credential.offer.renewed";
    static final String EVENT_FAILED = "credential.offer.renew.failed";
    static final String DENY_TENANT_MISMATCH = "tenant_mismatch";
    static final String DENY_NO_CREDENTIAL_TYPE = "no_credential_type";
    static final String DENY_MISSING_POWER = "missing_power";
    static final String DENY_READ_ONLY = "read_only";
    private static final String RESOURCE_TYPE = "issuance";
    private static final String UNKNOWN_ACTOR = "unknown";

    private final AccessTokenService accessTokenService;
    private final PolicyContextFactory policyContextFactory;
    private final IssuanceService issuanceService;
    private final CredentialOfferService credentialOfferService;
    private final AuditService auditService;

    @Override
    @Observed(name = "issuance.renew-offer", contextualName = "renew-credential-offer")
    public Mono<CredentialOfferRenewal> renewCredentialOffer(String authorizationHeader, String issuanceId,
                                                             String publicIssuerBaseUrl) {
        return resolveActor().flatMap(actor -> {
            RenewalAudit audit = new RenewalAudit(actor, issuanceId);
            return resolveRequester(authorizationHeader, audit)
                    .flatMap(requester -> requireTenantMatch(requester, audit))
                    .flatMap(requester -> parseIssuanceId(issuanceId)
                            .flatMap(id -> authorizeRenewal(requester, audit)
                                    .flatMap(ctx -> findIssuanceInScope(ctx, id))))
                    .flatMap(this::requireRenewable)
                    .flatMap(renewable -> deliverNewOffer(renewable, publicIssuerBaseUrl))
                    .doOnSuccess(audit::renewed)
                    .doOnError(audit::failed);
        });
    }

    /** What the access token says about the requester: role and scope, and powers and tenant. */
    private record Requester(AuthorizationContext authorization, PolicyContext policy) {}

    /**
     * A genuine token that does not say which credential the requester holds ({@code credential_type}
     * missing, or a type without a profile) cannot be authorized: 403 {@code insufficient_permission}
     * of the contract, not the shared API's 400 (EUD-295 review W5).
     */
    private Mono<Requester> resolveRequester(String authorizationHeader, RenewalAudit audit) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            Mono<PolicyContext> policy = accessTokenService.getCleanBearerToken(authorizationHeader)
                    .flatMap(token -> policyContextFactory.fromTokenSimple(token, tenantDomain))
                    .onErrorMap(ex -> ex instanceof JWTClaimMissingException
                                    || ex instanceof InvalidCredentialFormatException,
                            ex -> {
                                log.info("Credential offer renewal denied: the token has no usable credential type");
                                audit.denied(DENY_NO_CREDENTIAL_TYPE);
                                return new RenewalPermissionDeniedException(
                                        "The token does not say which credential the requester holds");
                            });
            return accessTokenService.getAuthorizationContext(authorizationHeader)
                    .doOnNext(audit::requester)
                    .zipWith(policy, Requester::new);
        });
    }

    /**
     * The token must be for the tenant of the request, as when issuing ({@link RequireTenantMatchRule}).
     * Decided here, not by a filter: in this issuer each endpoint applies it.
     */
    private Mono<Requester> requireTenantMatch(Requester requester, RenewalAudit audit) {
        return new RequireTenantMatchRule().evaluate(requester.policy(), null)
                .onErrorMap(TenantMismatchException.class, ex -> {
                    log.info("Credential offer renewal rejected: {}", ex.getMessage());
                    audit.denied(DENY_TENANT_MISMATCH);
                    return new RenewalTenantMismatchException("The token is for another tenant");
                })
                .thenReturn(requester);
    }

    private Mono<UUID> parseIssuanceId(String issuanceId) {
        try {
            return Mono.just(UUID.fromString(issuanceId));
        } catch (IllegalArgumentException _) {
            return Mono.error(new RenewalInvalidIssuanceIdException("The issuance id is not a UUID"));
        }
    }

    // ── Authorization: the single point EUD-272 replaces ─────────────────────────────────────
    // TODO(EUD-272): replace both steps with PowerAuthorizationService.authorize(E1|E2, organization
    // of the issuance, id) -- the exact power for the attestation type, on its organization.

    /**
     * Permission, without the resource: the requester may issue today (platform administrator, or
     * {@code Onboarding/Execute} or {@code Certification/Attest}) and may write (not the platform's
     * read-only view).
     */
    private Mono<AuthorizationContext> authorizeRenewal(Requester requester, RenewalAudit audit) {
        AuthorizationContext ctx = requester.authorization();
        String basis = permissionBasis(ctx, requester.policy());
        if (!ctx.canWrite() || basis == null) {
            log.info("Credential offer renewal denied: role={}, canWrite={}, mayIssue={}",
                    ctx.role(), ctx.canWrite(), basis != null);
            audit.denied(ctx.canWrite() ? DENY_MISSING_POWER : DENY_READ_ONLY);
            return Mono.error(new RenewalPermissionDeniedException("The requester may not renew credential offers"));
        }
        audit.permitted(basis);
        return Mono.just(ctx);
    }

    /** What lets the requester issue today, as the audit records it; {@code null} if nothing does. */
    private static String permissionBasis(AuthorizationContext ctx, PolicyContext policyContext) {
        if (ctx.isSysAdmin()) {
            return BASIS_PLATFORM_ADMIN;
        }
        if (policyContext.hasPower(FN_ONBOARDING, ACT_EXECUTE)) {
            return FN_ONBOARDING + "/" + ACT_EXECUTE;
        }
        if (policyContext.hasPower(FN_CERTIFICATION, ACT_ATTEST)) {
            return FN_CERTIFICATION + "/" + ACT_ATTEST;
        }
        return null;
    }

    /**
     * Scope, as {@code GET /api/v1/issuances/{id}}: a tenant administrator, the whole tenant; anyone
     * else, their organization. Out of scope answers exactly like an issuance that does not exist.
     */
    private Mono<Issuance> findIssuanceInScope(AuthorizationContext ctx, UUID id) {
        Mono<Issuance> issuance = ctx.isTenantAdmin()
                ? issuanceService.getIssuanceById(id.toString())
                : issuanceService.getIssuanceByIdAndOrganization(id, ctx.organizationIdentifier());
        return issuance.switchIfEmpty(Mono.error(new RenewalIssuanceNotFoundException("Issuance not found")));
    }

    // ── Status and delivery mode ────────────────────────────────────────────────────────────

    private record RenewableIssuance(Issuance issuance, DeliveryMode mode) {}

    private Mono<RenewableIssuance> requireRenewable(Issuance issuance) {
        if (issuance.getCredentialStatus() != CredentialStatusEnum.DRAFT) {
            log.info("Credential offer renewal rejected: issuance={} status={}",
                    issuance.getIssuanceId(), issuance.getCredentialStatus());
            return Mono.error(new OfferNotRenewableException("The issuance is no longer a draft"));
        }
        return issuance.offerDeliveryMode()
                .map(mode -> Mono.just(new RenewableIssuance(issuance, mode)))
                .orElseGet(() -> {
                    log.info("Credential offer renewal rejected: issuance={} delivery={}",
                            issuance.getIssuanceId(), issuance.getDelivery());
                    return Mono.error(new OfferNotRenewableException("The issuance has no credential offer"));
                });
    }

    // ── Delivery ────────────────────────────────────────────────────────────────────────────

    private Mono<CredentialOfferRenewal> deliverNewOffer(RenewableIssuance renewable, String publicIssuerBaseUrl) {
        Issuance issuance = renewable.issuance();
        DeliveryMode mode = renewable.mode();
        String grantType = issuance.getGrantType() != null ? issuance.getGrantType() : AUTHORIZATION_CODE;

        // CredentialOfferService voids the previous offer only once the new one is delivered; an
        // offer that reached nobody is voided itself, so a failure here changes nothing (NFR-1).
        return credentialOfferService.createAndDeliverCredentialOffer(
                        issuance.getIssuanceId().toString(), issuance.getCredentialType(), grantType,
                        issuance.getEmail(), mode.value, issuance.getCredentialOfferRefreshToken(),
                        publicIssuerBaseUrl)
                .onErrorMap(ex -> {
                    log.error("Credential offer renewal failed for issuance={}: {}",
                            issuance.getIssuanceId(), ex.getMessage(), ex);
                    return new RenewalDeliveryFailedException("The credential offer could not be created");
                })
                .flatMap(result -> toRenewal(issuance, mode, result));
    }

    private Mono<CredentialOfferRenewal> toRenewal(Issuance issuance, DeliveryMode mode, CredentialOfferResult result) {
        if (mode == DeliveryMode.EMAIL && result.emailError() != null) {
            log.warn("Credential offer renewal email failed for issuance={}", issuance.getIssuanceId());
            return Mono.error(new RenewalDeliveryFailedException("The credential offer email could not be sent"));
        }
        log.info("Credential offer renewed for issuance={} mode={}", issuance.getIssuanceId(), mode.value);
        return Mono.just(new CredentialOfferRenewal(mode, mode == DeliveryMode.UI ? result.credentialOfferUri() : null));
    }

    // ── Audit ───────────────────────────────────────────────────────────────────────────────

    /** The authenticated principal, as the revocation records it. */
    private static Mono<String> resolveActor() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth != null && auth.isAuthenticated() && auth.getName() != null)
                .map(Authentication::getName)
                .defaultIfEmpty(UNKNOWN_ACTOR);
    }

    /**
     * The audit trail of one renewal: every permission decision (permitted, or denied with its
     * reason) and the outcome, with the actor, their organization and role, and the issuance. Best
     * effort: a failure of the audit channel is logged and never fails the renewal.
     */
    private final class RenewalAudit {

        private final String actor;
        private final String issuanceId;
        private AuthorizationContext requester;

        private RenewalAudit(String actor, String issuanceId) {
            this.actor = actor;
            this.issuanceId = issuanceId;
        }

        void requester(AuthorizationContext ctx) {
            this.requester = ctx;
        }

        void permitted(String basis) {
            Map<String, Object> details = details();
            details.put("basis", basis);
            safely(() -> auditService.auditSuccess(EVENT_PERMITTED, actor, RESOURCE_TYPE, issuanceId, details));
        }

        void denied(String reason) {
            safely(() -> auditService.auditFailure(EVENT_DENIED, actor, reason, details()));
        }

        void renewed(CredentialOfferRenewal renewal) {
            Map<String, Object> details = details();
            details.put("mode", renewal.mode().value);
            safely(() -> auditService.auditSuccess(EVENT_RENEWED, actor, RESOURCE_TYPE, issuanceId, details));
        }

        /** The outcome of a renewal that was not denied; denials are audited where they are decided. */
        void failed(Throwable error) {
            String reason = switch (error) {
                case RenewalInvalidIssuanceIdException _ -> "invalid_issuance_id";
                case RenewalIssuanceNotFoundException _ -> "issuance_not_found";
                case OfferNotRenewableException _ -> "offer_not_renewable";
                case RenewalDeliveryFailedException _ -> "delivery_failed";
                case RenewalPermissionDeniedException _, RenewalTenantMismatchException _ -> null;
                default -> "unexpected_error";
            };
            if (reason != null) {
                safely(() -> auditService.auditFailure(EVENT_FAILED, actor, reason, details()));
            }
        }

        private Map<String, Object> details() {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("issuanceId", issuanceId);
            if (requester != null) {
                details.put("organizationIdentifier", requester.organizationIdentifier());
                details.put("role", String.valueOf(requester.role()));
            }
            return details;
        }

        private void safely(Runnable audit) {
            try {
                audit.run();
            } catch (RuntimeException e) {
                log.warn("Credential offer renewal audit failed for issuance={}: {}", issuanceId, e.toString());
            }
        }
    }
}
