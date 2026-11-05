package es.in2.issuer.backend.issuance.application.workflow.impl;

import es.in2.issuer.backend.issuance.application.workflow.CredentialOfferRenewalWorkflow;
import es.in2.issuer.backend.issuance.domain.exception.OfferNotRenewableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalContentNotDecidableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalDeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalInvalidIssuanceIdException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalIssuanceNotFoundException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalPermissionDeniedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalTenantMismatchException;
import es.in2.issuer.backend.issuance.domain.model.CredentialOfferRenewal;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.domain.util.IssuanceIds;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.AUTHORIZATION_CODE;

/**
 * Checks run in the order of the acceptance contract (EUD-295 ac.md): tenant of the token, id
 * format, permission and scope -- decided by the decision point of EUD-272 as issuing the stored
 * process again (base action for its type, E2 for another organization, grant rules for its
 * content, type enabled) -- and last status and delivery mode. Authentication and the volume limit are decided earlier by the web filters.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferRenewalWorkflowImpl implements CredentialOfferRenewalWorkflow {

    // Audit events of the outcome (conv-quality-security-gates §3.4, ENS op.exp.8). The permission
    // decision, permitted or denied, is traced by the decision point (authorization.permit/deny).
    static final String EVENT_RENEWED = "credential.offer.renewed";
    static final String EVENT_FAILED = "credential.offer.renew.failed";
    static final String EVENT_CANCELLED = "credential.offer.renew.cancelled";
    private static final String RESOURCE_TYPE = "issuance";
    /** Resource id audited for a path id that is not an issuance id, as the decision point traces it. */
    static final String MALFORMED_ID = "<malformed>";
    private static final String NOT_FOUND_DETAIL = "Issuance not found";

    private final CallerProvider callerProvider;
    private final PowerAuthorizationService powerAuthorizationService;
    private final IssuanceService issuanceService;
    private final CredentialProfileCatalog credentialProfileCatalog;
    private final GenericCredentialBuilder credentialBuilder;
    private final CredentialOfferService credentialOfferService;
    private final AuditService auditService;

    @Override
    @Observed(name = "issuance.renew-offer", contextualName = "renew-credential-offer")
    public Mono<CredentialOfferRenewal> renewCredentialOffer(String issuanceId, String publicIssuerBaseUrl) {
        return callerProvider.current().flatMap(caller -> {
            RenewalAudit audit = new RenewalAudit(caller, issuanceId);
            return requireTenantMatch(caller)
                    .then(Mono.defer(() -> parseIssuanceId(issuanceId)))
                    .flatMap(id -> findAuthorizedIssuance(caller, id))
                    .flatMap(this::requireRenewable)
                    .flatMap(renewable -> deliverNewOffer(renewable, publicIssuerBaseUrl))
                    .doOnNext(audit::renewed)
                    .doOnError(audit::failed)
                    .doOnCancel(audit::cancelled);
        });
    }

    /**
     * The token must be for the tenant of the request (FR-02 of EUD-253), decided -- and traced --
     * by the decision point before anything else, as the order of the contract fixes.
     */
    private Mono<Void> requireTenantMatch(Caller caller) {
        return powerAuthorizationService.recognize(caller)
                .onErrorMap(TenantMismatchException.class, ex -> {
                    log.info("Credential offer renewal rejected: {}", ex.getMessage());
                    return new RenewalTenantMismatchException("The token is for another tenant");
                })
                .then();
    }

    private static Mono<UUID> parseIssuanceId(String issuanceId) {
        return IssuanceIds.parse(issuanceId)
                .map(Mono::just)
                .orElseGet(() -> Mono.error(new RenewalInvalidIssuanceIdException("The issuance id is not a UUID")));
    }

    // ── Authorization: the single point of the renewal ─────────────────────────────────────────

    /**
     * Who may renew is who may issue the stored process again (decision 1 of the EUD-295 review,
     * round 3): the same actions as issuing it, on the organization stored with it. Who may not issue
     * at all gets 403 whether or not the issuance exists; an issuance out of scope answers like one
     * that does not exist (AC-06, AC-11).
     */
    private Mono<Issuance> findAuthorizedIssuance(Caller caller, UUID id) {
        String resourceId = id.toString();
        return issuanceService.getIssuanceById(resourceId)
                .flatMap(issuance -> authorizeReissue(caller, issuance, resourceId).thenReturn(issuance))
                .switchIfEmpty(Mono.defer(() -> authorizeWithoutResource(caller, resourceId)
                        .then(Mono.error(new RenewalIssuanceNotFoundException(NOT_FOUND_DETAIL)))))
                .onErrorMap(LearIssuancePolicyException.class,
                        ex -> new RenewalPermissionDeniedException("The requester may not renew credential offers"))
                .onErrorMap(IssuanceNotFoundException.class,
                        ex -> new RenewalIssuanceNotFoundException(NOT_FOUND_DETAIL))
                .onErrorMap(TenantMismatchException.class,
                        ex -> new RenewalTenantMismatchException("The token is for another tenant"));
    }

    /**
     * An id that is not in the tenant has no type to decide on: who may issue anything -- E1, or E6
     * for product certifications -- learns it does not exist; anyone else is denied (AC-11).
     */
    private Mono<Void> authorizeWithoutResource(Caller caller, String resourceId) {
        return powerAuthorizationService.authorize(PowerAuthorizationService.ISSUE_OWN, caller, null, resourceId)
                .onErrorResume(LearIssuancePolicyException.class, notE1 -> powerAuthorizationService.authorize(
                        PowerAuthorizationService.ISSUE_PRODUCT_CERTIFICATION, caller, null, resourceId))
                .then();
    }

    /**
     * Decides the stored process as an issuance of its type and content. A process whose type is no
     * longer known or whose content cannot be read is denied: what it would grant cannot be decided
     * (fail closed, EUD-295 tasks.md note 9). The decision point never sees it, so the renewal audits it.
     */
    private Mono<Void> authorizeReissue(Caller caller, Issuance issuance, String resourceId) {
        String configurationId = issuance.getCredentialType();
        CredentialProfile profile = configurationId != null
                ? credentialProfileCatalog.getByConfigurationId(configurationId) : null;
        Optional<JsonNode> payload = profile != null
                ? credentialBuilder.extractPayload(profile, issuance.getCredentialDataSet()) : Optional.empty();
        if (payload.isEmpty()) {
            log.warn("Credential offer renewal denied: issuance={} type={} has no readable content to decide on",
                    resourceId, configurationId);
            return Mono.error(new RenewalContentNotDecidableException("The stored content cannot be decided"));
        }
        String organization = Objects.requireNonNullElse(issuance.getOrganizationIdentifier(), "");
        return powerAuthorizationService.authorizeReissue(caller, resourceId, configurationId,
                        profile.credentialType(), organization, payload.get())
                .then();
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

    /**
     * The outcome of one renewal: renewed with its mode, failed with its reason, or cancelled by the
     * client. The caller is identified as the decision point traces it -- its attestation, or the
     * access token -- never by the mandatee's email (conv-quality-security-gates §10.3). Best effort:
     * a failure of the audit channel is logged and never fails the renewal.
     */
    private final class RenewalAudit {

        private final String actor;
        private final String callerOrganization;
        private final String resourceId;

        private RenewalAudit(Caller caller, String issuanceId) {
            this.actor = actorOf(caller);
            this.callerOrganization = caller.organizationIdentifier();
            this.resourceId = IssuanceIds.parse(issuanceId).map(UUID::toString).orElse(MALFORMED_ID);
        }

        void renewed(CredentialOfferRenewal renewal) {
            Map<String, Object> details = details();
            details.put("mode", renewal.mode().value);
            safely(() -> auditService.auditSuccess(EVENT_RENEWED, actor, RESOURCE_TYPE, resourceId, details));
        }

        /** Denials are traced by the decision point, with their reason; the rest of the failures here. */
        void failed(Throwable error) {
            String reason = switch (error) {
                case RenewalInvalidIssuanceIdException _ -> "invalid_issuance_id";
                case RenewalIssuanceNotFoundException _ -> "issuance_not_found";
                case OfferNotRenewableException _ -> "offer_not_renewable";
                case RenewalContentNotDecidableException _ -> "content_not_decidable";
                case RenewalDeliveryFailedException _ -> "delivery_failed";
                case RenewalPermissionDeniedException _, RenewalTenantMismatchException _ -> null;
                default -> "unexpected_error";
            };
            if (reason != null) {
                safely(() -> auditService.auditFailure(EVENT_FAILED, actor, reason, details()));
            }
        }

        /** The client went away: the new offer is voided unless it already became the current one. */
        void cancelled() {
            safely(() -> auditService.auditFailure(EVENT_CANCELLED, actor, "cancelled", details()));
        }

        private Map<String, Object> details() {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("resourceId", resourceId);
            if (callerOrganization != null) {
                details.put("callerOrganization", callerOrganization);
            }
            return details;
        }

        private void safely(Runnable audit) {
            try {
                audit.run();
            } catch (RuntimeException e) {
                log.warn("Credential offer renewal audit failed for issuance={}: {}", resourceId, e.toString());
            }
        }
    }

    /** Who acted, as the decision point records it: the attestation, else the access token. */
    private static String actorOf(Caller caller) {
        if (caller.attestationId() != null) {
            return caller.attestationId();
        }
        return caller.tokenId() != null ? caller.tokenId() : caller.organizationIdentifier();
    }
}
