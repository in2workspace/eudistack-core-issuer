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
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

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

    private final AccessTokenService accessTokenService;
    private final PolicyContextFactory policyContextFactory;
    private final IssuanceService issuanceService;
    private final CredentialOfferService credentialOfferService;

    @Override
    @Observed(name = "issuance.renew-offer", contextualName = "renew-credential-offer")
    public Mono<CredentialOfferRenewal> renewCredentialOffer(String authorizationHeader, String issuanceId,
                                                             String publicIssuerBaseUrl) {
        return resolveRequester(authorizationHeader)
                .flatMap(this::requireTenantMatch)
                .flatMap(requester -> parseIssuanceId(issuanceId)
                        .flatMap(id -> authorizeRenewal(requester)
                                .flatMap(ctx -> findIssuanceInScope(ctx, id))))
                .flatMap(this::requireRenewable)
                .flatMap(renewable -> deliverNewOffer(renewable, publicIssuerBaseUrl));
    }

    /** What the access token says about the requester: role and scope, and powers and tenant. */
    private record Requester(AuthorizationContext authorization, PolicyContext policy) {}

    private Mono<Requester> resolveRequester(String authorizationHeader) {
        return Mono.deferContextual(reactorCtx -> {
            String tenantDomain = reactorCtx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            Mono<PolicyContext> policy = accessTokenService.getCleanBearerToken(authorizationHeader)
                    .flatMap(token -> policyContextFactory.fromTokenSimple(token, tenantDomain));
            return accessTokenService.getAuthorizationContext(authorizationHeader)
                    .zipWith(policy, Requester::new);
        });
    }

    /**
     * The token must be for the tenant of the request, as when issuing ({@link RequireTenantMatchRule}).
     * Decided here, not by a filter: in this issuer each endpoint applies it.
     */
    private Mono<Requester> requireTenantMatch(Requester requester) {
        return new RequireTenantMatchRule().evaluate(requester.policy(), null)
                .onErrorMap(TenantMismatchException.class, ex -> {
                    log.info("Credential offer renewal rejected: {}", ex.getMessage());
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
    private Mono<AuthorizationContext> authorizeRenewal(Requester requester) {
        AuthorizationContext ctx = requester.authorization();
        boolean mayIssue = ctx.isSysAdmin() || hasIssuingPower(requester.policy());
        if (!ctx.canWrite() || !mayIssue) {
            log.info("Credential offer renewal denied: role={}, canWrite={}, mayIssue={}",
                    ctx.role(), ctx.canWrite(), mayIssue);
            return Mono.error(new RenewalPermissionDeniedException("The requester may not renew credential offers"));
        }
        return Mono.just(ctx);
    }

    private boolean hasIssuingPower(PolicyContext policyContext) {
        return policyContext.hasPower(FN_ONBOARDING, ACT_EXECUTE)
                || policyContext.hasPower(FN_CERTIFICATION, ACT_ATTEST);
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
}
