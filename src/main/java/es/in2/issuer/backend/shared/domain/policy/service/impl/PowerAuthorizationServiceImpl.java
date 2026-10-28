package es.in2.issuer.backend.shared.domain.policy.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException.Reason;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.port.AuthorizationMatrixProvider;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix.ActionRule;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix.Scope;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix.UserTypeRule;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.IssuanceAuthorization;
import es.in2.issuer.backend.shared.domain.policy.RecognizedCaller;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static es.in2.issuer.backend.shared.domain.util.Constants.PLATFORM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Registered as a bean by {@code PowerAuthorizationConfig} (infrastructure): the decision point is
 * domain code and imports nothing from Spring (hexagonal-discipline).
 */
@Slf4j
@RequiredArgsConstructor
public class PowerAuthorizationServiceImpl implements PowerAuthorizationService {

    static final String EVENT_PERMIT = "authorization.permit";
    static final String EVENT_DENY = "authorization.deny";
    static final String RESOURCE_OUT_OF_SCOPE = "resource_out_of_scope";

    /** Denial code of each action that is not simply "the caller has no power for it". */
    private static final Map<String, Reason> DENIAL_REASONS = Map.of(
            ISSUE_ON_BEHALF, Reason.ON_BEHALF_REQUIRES_TENANT_ADMIN,
            "E3", Reason.ONBOARDING_DELEGATION_REQUIRES_TENANT_ADMIN,
            "E4", Reason.TENANT_ADMIN_DELEGATION_REQUIRES_PLATFORM_ADMIN,
            "E5", Reason.CERTIFICATION_DELEGATION_REQUIRES_TENANT_ADMIN,
            "E9", Reason.FOREIGN_DOMAIN_DELEGATION_REQUIRES_PLATFORM_ADMIN,
            ISSUE_PRODUCT_CERTIFICATION, Reason.CERTIFICATION_POWER_REQUIRED);

    private final AuthorizationMatrixProvider matrixProvider;
    private final CallerProvider callerProvider;
    private final TenantCredentialProfileService tenantCredentialProfileService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<RecognizedCaller> recognize(Caller caller) {
        return requestTenant().flatMap(tenant -> Mono.fromCallable(() -> {
            requireTenantMatch(caller, tenant, new Trace(null, caller, tenant));
            return recognize(matrixProvider.current(), caller, tenant);
        }));
    }

    @Override
    public Mono<AuthorizationDecision> authorize(String actionId, String resourceOrganization, String resourceId) {
        return callerProvider.current()
                .flatMap(caller -> authorize(actionId, caller, resourceOrganization, resourceId));
    }

    @Override
    public Mono<AuthorizationDecision> authorize(String actionId, Caller caller, String resourceOrganization,
                                                 String resourceId) {
        return requestTenant().flatMap(tenant -> Mono.defer(() -> {
            AuthorizationMatrix matrix = matrixProvider.current();
            Trace trace = new Trace(actionId, caller, tenant)
                    .with("resourceOrganization", resourceOrganization)
                    .with("resourceId", resourceId);
            requireTenantMatch(caller, tenant, trace);
            RecognizedCaller recognized = recognize(matrix, caller, tenant);
            trace.recognized(recognized, recognizingPower(matrix, recognized));

            Scope scope;
            try {
                scope = evaluate(matrix.action(actionId), actionId, recognized, trace);
            } catch (LearIssuancePolicyException denied) {
                return Mono.error(denied);
            }
            if (scope == Scope.OWN_ORGANIZATION && resourceOrganization != null
                    && !resourceOrganization.equals(recognized.organizationIdentifier())) {
                deny(trace, RESOURCE_OUT_OF_SCOPE);
                return Mono.error(new IssuanceNotFoundException("No issuance found for issuanceId: " + resourceId));
            }
            permit(trace.with("scope", scope.value()));
            return Mono.just(new AuthorizationDecision(actionId, recognized, scope));
        }));
    }

    @Override
    public Mono<IssuanceAuthorization> authorizeIssuance(String processId, String credentialConfigurationId, String credentialType,
                                                         String requestedOrganization, JsonNode payload) {
        return callerProvider.current()
                .flatMap(caller -> requestTenant().flatMap(tenant -> Mono.defer(() -> {
                    AuthorizationMatrix matrix = matrixProvider.current();
                    Trace trace = new Trace(ISSUE_OWN, caller, tenant)
                            .with("processId", processId)
                            .with("credentialConfigurationId", credentialConfigurationId);
                    requireTenantMatch(caller, tenant, trace);
                    RecognizedCaller recognized = recognize(matrix, caller, tenant);
                    trace.recognized(recognized, recognizingPower(matrix, recognized));

                    String organization = requestedOrganization == null || requestedOrganization.isBlank()
                            ? caller.organizationIdentifier() : requestedOrganization;
                    trace.with("organization", organization);

                    List<String> actionIds = issuanceActions(matrix, List.of(credentialConfigurationId, String.valueOf(credentialType)),
                            organization, caller, payload, tenant);
                    try {
                        for (String actionId : actionIds) {
                            trace.action(actionId);
                            evaluate(matrix.action(actionId), actionId, recognized, trace);
                        }
                    } catch (LearIssuancePolicyException denied) {
                        return Mono.error(denied);
                    }
                    trace.action(String.join(",", actionIds));

                    return requireTypeEnabled(credentialConfigurationId, trace)
                            .then(Mono.fromSupplier(() -> {
                                permit(trace);
                                return new IssuanceAuthorization(recognized, organization, actionIds);
                            }));
                })));
    }

    /**
     * The actions an issuance needs: the base one for its type (E6 for product certifications, E1
     * otherwise), E2 when it is for another organization, and one grant action per power it carries.
     */
    private List<String> issuanceActions(AuthorizationMatrix matrix, List<String> typeNames, String organization,
                                         Caller caller, JsonNode payload, String tenant) {
        List<String> ids = new ArrayList<>();
        ActionRule certification = matrix.action(ISSUE_PRODUCT_CERTIFICATION);
        boolean productCertification = certification != null && certification.credentialTypesOrEmpty().stream()
                .anyMatch(pattern -> typeNames.stream().anyMatch(name -> typeMatches(pattern, name)));
        ids.add(productCertification ? ISSUE_PRODUCT_CERTIFICATION : ISSUE_OWN);
        if (!Objects.equals(organization, caller.organizationIdentifier())) {
            ids.add(ISSUE_ON_BEHALF);
        }
        for (Power granted : grantedPowers(payload)) {
            String grantAction = grantAction(matrix, granted, tenant);
            if (grantAction != null && !ids.contains(grantAction)) {
                ids.add(grantAction);
            }
        }
        return ids;
    }

    /** A type of the matrix, exact or, ending in {@code *}, a whole family ({@code gx.labelcredential.*}). */
    private static boolean typeMatches(String pattern, String typeName) {
        return pattern.endsWith("*")
                ? typeName.startsWith(pattern.substring(0, pattern.length() - 1))
                : pattern.equals(typeName);
    }

    /**
     * The grant action that decides who may put this power in an attestation, or null when no rule
     * covers it. A power is outside the tenant when its domain is not the tenant's, and always when
     * it is a platform domain ({@code EUDISTACK}): a tenant named like one does not make the
     * platform administrator's power its own.
     */
    private String grantAction(AuthorizationMatrix matrix, Power granted, String tenant) {
        boolean outsideTenant = granted.domain() == null || !granted.domain().equalsIgnoreCase(tenant)
                || matrix.isPlatformDomain(granted.domain());
        for (ActionRule action : matrix.actions()) {
            if (outsideTenant && action.grantsOutsideTenant()) {
                return action.id();
            }
            if (!outsideTenant && action.grants() != null && action.grants().isGrantedBy(granted, tenant)) {
                return action.id();
            }
        }
        return null;
    }

    /**
     * The powers the attestation grants. A power may name a field twice, plain and with its {@code tmf_}
     * alias; consumers do not agree on which one they read, so a power whose two readings differ is
     * decided under both and the grant rules must cover each.
     */
    private List<Power> grantedPowers(JsonNode payload) {
        JsonNode powers = payload != null ? payload.path("power") : null;
        if (powers == null || !powers.isArray()) {
            return List.of();
        }
        List<Power> readings = new ArrayList<>();
        for (JsonNode item : powers) {
            Power plain = reading(item, false);
            Power alias = reading(item, true);
            readings.add(plain);
            if (!plain.equals(alias)) {
                readings.add(alias);
            }
        }
        return readings;
    }

    private Power reading(JsonNode item, boolean aliasFirst) {
        JsonNode action = field(item, "action", aliasFirst);
        return new Power(action == null ? null : objectMapper.convertValue(action, Object.class),
                text(field(item, "domain", aliasFirst)), text(field(item, "function", aliasFirst)),
                text(field(item, "type", aliasFirst)));
    }

    private static JsonNode field(JsonNode item, String name, boolean aliasFirst) {
        JsonNode plain = item.get(name);
        JsonNode alias = item.get("tmf_" + name);
        JsonNode first = aliasFirst ? alias : plain;
        JsonNode second = aliasFirst ? plain : alias;
        return first != null && !first.isNull() ? first : second != null && !second.isNull() ? second : null;
    }

    private static String text(JsonNode node) {
        return node == null ? null : node.isTextual() ? node.asText() : node.toString();
    }

    /** Returns the caller's scope on the action, or throws when the action is denied. */
    private Scope evaluate(ActionRule action, String actionId, RecognizedCaller recognized, Trace trace)
            throws LearIssuancePolicyException {
        if (action == null) {
            throw deny(trace, Reason.AUTHORIZATION_RULE_MISSING, "no rule for action " + actionId);
        }
        if (action.isWrite() && recognized.readOnly()) {
            throw deny(trace, Reason.PLATFORM_TENANT_READ_ONLY, "actions that write are not allowed from the platform tenant");
        }
        if (action.requiresPower() != null) {
            trace.with("powerEvaluated", action.requiresPower().toString());
            boolean held = recognized.caller().powers().stream()
                    .anyMatch(p -> action.requiresPower().isHeldBy(p, recognized.tenant()));
            if (!held) {
                throw deny(trace, reasonFor(actionId), "missing power " + action.requiresPower());
            }
        }
        Scope scope = action.scope().get(recognized.userType());
        if (scope == null || scope == Scope.DENY) {
            throw deny(trace, reasonFor(actionId), "action " + actionId + " not allowed for " + recognized.userType());
        }
        if (ISSUE_ON_BEHALF.equals(actionId) && scope != Scope.ANY_ORGANIZATION) {
            throw deny(trace, reasonFor(actionId), "action " + actionId + " needs scope on any organization");
        }
        return scope;
    }

    private static Reason reasonFor(String actionId) {
        return DENIAL_REASONS.getOrDefault(actionId, Reason.OPERATOR_LACKS_ONBOARDING);
    }

    /** The first user type of the recognition order whose power the caller holds (FR-03). */
    static RecognizedCaller recognize(AuthorizationMatrix matrix, Caller caller, String tenant) {
        for (String typeId : matrix.recognitionOrder()) {
            UserTypeRule rule = matrix.userTypes().get(typeId);
            List<AuthorizationMatrix.PowerPattern> patterns = rule.recognizedByOrEmpty();
            boolean recognized = patterns.isEmpty() || caller.powers().stream()
                    .anyMatch(power -> patterns.stream().anyMatch(pattern -> pattern.isHeldBy(power, tenant)));
            if (recognized) {
                boolean platformTenant = PLATFORM_TENANT.equals(tenant);
                boolean readOnly = rule.readOnlyInPlatformTenant() && platformTenant;
                return new RecognizedCaller(caller, tenant, typeId,
                        rule.actsAs() != null ? rule.actsAs() : typeId,
                        readOnly, rule.securityTrace() && !platformTenant);
            }
        }
        throw new IllegalStateException("Authorization matrix recognizes no user type (missing a catch-all type)");
    }

    /** FR-13: the caller's power that gave it its user type, on which every scope decision rests. */
    private static String recognizingPower(AuthorizationMatrix matrix, RecognizedCaller recognized) {
        List<AuthorizationMatrix.PowerPattern> patterns = matrix.userTypes().get(recognized.userType()).recognizedByOrEmpty();
        return recognized.caller().powers().stream()
                .filter(power -> patterns.stream().anyMatch(pattern -> pattern.isHeldBy(power, recognized.tenant())))
                .findFirst()
                .map(power -> power.type() + " · " + power.domain() + " · " + power.function() + " · " + actionsOf(power))
                .orElse(null);
    }

    private static String actionsOf(Power power) {
        return power.action() instanceof List<?> actions
                ? String.join(",", actions.stream().map(String::valueOf).toList())
                : String.valueOf(power.action());
    }

    /** FR-02: the token must have been issued for the request's tenant, also for the platform administrator. */
    private void requireTenantMatch(Caller caller, String tenant, Trace trace) {
        String tokenTenant = caller.tokenTenant();
        if (tokenTenant == null || tokenTenant.isBlank() || !tokenTenant.equalsIgnoreCase(tenant)) {
            deny(trace, "tenant_mismatch");
            throw new TenantMismatchException("Token tenant '" + tokenTenant
                    + "' does not match tenant header '" + tenant + "'");
        }
    }

    /** FR-07: only the types enabled in the tenant are issued. */
    private Mono<Void> requireTypeEnabled(String credentialConfigurationId, Trace trace) {
        return tenantCredentialProfileService.isProfileAllowed(credentialConfigurationId)
                .flatMap(allowed -> {
                    if (Boolean.TRUE.equals(allowed)) {
                        return Mono.empty();
                    }
                    return Mono.error(deny(trace, Reason.CREDENTIAL_TYPE_NOT_ENABLED,
                            "credential type " + credentialConfigurationId + " is not enabled in the tenant"));
                });
    }

    /** The tenant of the request, set from {@code X-Tenant} by {@code TenantDomainWebFilter} (FR-01). */
    private static Mono<String> requestTenant() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null);
            if (tenant == null || tenant.isBlank()) {
                return Mono.error(new TenantMismatchException("Tenant context is required (missing X-Tenant header)"));
            }
            return Mono.just(tenant);
        });
    }

    private LearIssuancePolicyException deny(Trace trace, Reason reason, String message) {
        deny(trace, reason.getCode());
        return new LearIssuancePolicyException(reason, "Authorization denied: " + message);
    }

    private void deny(Trace trace, String reason) {
        try {
            auditService.auditFailure(EVENT_DENY, trace.actor(), reason, trace.details());
        } catch (RuntimeException e) {
            log.warn("Failed to audit authorization denial: {}", e.toString());
        }
    }

    private void permit(Trace trace) {
        try {
            auditService.auditSuccess(EVENT_PERMIT, trace.actor(), "action", trace.actionId, trace.details());
        } catch (RuntimeException e) {
            log.warn("Failed to audit authorization permit: {}", e.toString());
        }
    }

    /** What the trace of a decision says (FR-13): who, which power, on which resource, and the outcome. */
    private static final class Trace {
        private final Map<String, Object> details = new LinkedHashMap<>();
        private final Caller caller;
        private String actionId;

        Trace(String actionId, Caller caller, String tenant) {
            this.caller = caller;
            action(actionId);
            with("tenant", tenant);
            with("callerOrganization", caller.organizationIdentifier());
            with("callerCredentialType", caller.credentialType());
            with("callerTokenId", caller.tokenId());
            with("callerAttestationId", caller.attestationId());
        }

        Trace action(String id) {
            this.actionId = id;
            return with("action", id);
        }

        Trace recognized(RecognizedCaller recognized, String recognizedByPower) {
            with("userType", recognized.userType());
            with("recognizedByPower", recognizedByPower);
            with("actsAs", recognized.actsAs());
            return with("securityAction", recognized.securityAction());
        }

        Trace with(String key, Object value) {
            if (value != null) {
                details.put(key, value);
            }
            return this;
        }

        /**
         * Who acted, without personal data (conv-quality-security-gates §10.3): the attestation, or
         * the access token when the token does not carry the attestation id.
         */
        String actor() {
            if (caller.attestationId() != null) {
                return caller.attestationId();
            }
            return caller.tokenId() != null ? caller.tokenId() : caller.organizationIdentifier();
        }

        Map<String, Object> details() {
            return Collections.unmodifiableMap(new LinkedHashMap<>(details));
        }
    }
}
