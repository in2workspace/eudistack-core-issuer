package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryChange;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.SYSTEM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Records the changes to the entries of the attestation catalog as {@code CatalogEntryChanged} audit events
 * (EUD-266, AC-12), the name and the {@code details} of the EUD-244 audit catalogue: {@code operation}
 * ({@code Create}, {@code Update}, {@code Enable} or {@code Disable}), {@code credential_configuration_id}
 * and, only for an {@code Update}, {@code changes}, the fields that differ with their old and new value.
 * One event per committed change; and one {@code Denied} event, with its reason, for a write the catalog
 * refused ({@link #POLICY_DENIED}, {@link #INVALID_CONFIGURATION}).
 *
 * <p>"Who" is the person behind the request, as the verified access token names it, and not the
 * administrator organization. The organization
 * is recorded next to the person and not in the details, as the canonical {@code organization} of the EUD-244
 * audit record: the details carry only the fields the catalogue declares, and without the organization nothing
 * would say whom the person acted for (the email is masked in the logs).
 * Both are read from the verified access token of the request through {@link CallerProvider}, so the callers only hand over what happened and
 * call this once the transaction has committed.
 *
 * <p>Best-effort: the change is already committed and cannot be undone, so a failure to resolve the
 * identity or to write the event is logged and never fails the request.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CatalogEntryChangeAuditor {

    static final String EVENT = "CatalogEntryChanged";
    static final String RESOURCE_TYPE = "attestation-catalog";
    static final String UNKNOWN = "unknown";
    /** The caller is not allowed to write the catalog. */
    public static final String POLICY_DENIED = "PolicyDenied";
    /** The write was rejected for a business reason: the configuration is not valid for the schema. */
    public static final String INVALID_CONFIGURATION = "InvalidConfiguration";

    private final AuditService auditService;
    private final CallerProvider callerProvider;
    private final AuditTrailPort auditTrail;

    public Mono<Void> audit(CatalogEntryChange change) {
        return auditAll(List.of(change));
    }

    /** One event per change; the person and the organization are resolved once for all of them. */
    public Mono<Void> auditAll(List<CatalogEntryChange> changes) {
        if (changes.isEmpty()) {
            return Mono.empty();
        }
        return Mono.deferContextual(ctx -> {
                    String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
                    return Mono.zip(resolveActor(), resolveOrganization())
                            .doOnNext(who -> changes.forEach(change ->
                                    auditService.auditSuccess(EVENT, who.getT1(), who.getT2(), RESOURCE_TYPE,
                                            tenant, details(change))))
                            .then(Flux.fromIterable(changes).concatMap(this::stageChange).then());
                })
                .onErrorResume(e -> {
                    log.warn("Catalog audit: could not record {} change(s), error={}", changes.size(), e.toString());
                    return Mono.empty();
                });
    }

    /**
     * A {@code Denied} event for a write that was refused. {@code operation} and
     * {@code credentialConfigurationId} are left out of the details when they are not known at that point
     * (a create knows its entry only once the schema resolves; an enable or a disable is told apart only by
     * the body, which is not read before the caller is authorized).
     *
     * @param reason {@link #POLICY_DENIED} or {@link #INVALID_CONFIGURATION}
     */
    public Mono<Void> auditDenied(CatalogEntryChange.Operation operation, String credentialConfigurationId,
                                  String reason) {
        return Mono.zip(resolveActor(), resolveOrganization())
                .doOnNext(who -> {
                    Map<String, Object> details = new LinkedHashMap<>();
                    if (operation != null) {
                        details.put("operation", operation.value());
                    }
                    if (credentialConfigurationId != null) {
                        details.put("credential_configuration_id", credentialConfigurationId);
                    }
                    auditService.auditFailure(EVENT, who.getT1(), who.getT2(), reason, details);
                })
                .then(stageDenied(operation, credentialConfigurationId, reason))
                .onErrorResume(e -> {
                    log.warn("Catalog audit: could not record a denied {}, error={}", reason, e.toString());
                    return Mono.empty();
                });
    }

    /**
     * The same change for the audit store. Once the change has committed, so best effort: a broken audit
     * channel must neither undo it nor fail the request. The actor and organization come from the audit
     * context of the request, which reads them from the verified access token.
     */
    private Mono<Void> stageChange(CatalogEntryChange change) {
        return auditTrail.stageBestEffort(AuditEntry.success(AuditEventType.CATALOG_ENTRY_CHANGED,
                resourceOf(change.credentialConfigurationId()), details(change)));
    }

    /** Only when the entry is known: the catalogue's resource names it, and a refusal may come before that. */
    private Mono<Void> stageDenied(CatalogEntryChange.Operation operation, String credentialConfigurationId,
                                   String reason) {
        if (credentialConfigurationId == null) {
            return Mono.empty();
        }
        Map<String, Object> details = new LinkedHashMap<>();
        if (operation != null) {
            details.put("operation", operation.value());
        }
        details.put("credential_configuration_id", credentialConfigurationId);
        return auditTrail.stageBestEffort(AuditEntry.forReason(AuditEventType.CATALOG_ENTRY_CHANGED,
                resourceOf(credentialConfigurationId), reason, details));
    }

    private static String resourceOf(String credentialConfigurationId) {
        return "catalog-entry:" + credentialConfigurationId;
    }

    private static Map<String, Object> details(CatalogEntryChange change) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("operation", change.operation().value());
        details.put("credential_configuration_id", change.credentialConfigurationId());
        if (change.operation() == CatalogEntryChange.Operation.UPDATE) {
            details.put("changes", change.changes());
        }
        return details;
    }

    /**
     * The person behind the request, as its verified access token names it ({@link CallerProvider#currentPerson}),
     * never the principal name: that one comes from the {@code X-ID-Token} when the request carries one, and the
     * issuer does not verify its signature, so it could name somebody else (B1 of the EUD-323 review).
     */
    private Mono<String> resolveActor() {
        return callerProvider.currentPerson()
                .onErrorResume(e -> Mono.empty())
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("Catalog audit: the person is not resolvable from the access token");
                    return Mono.just(UNKNOWN);
                }));
    }

    private Mono<String> resolveOrganization() {
        return callerProvider.current()
                .map(Caller::organizationIdentifier)
                .onErrorResume(e -> {
                    log.warn("Catalog audit: the organization is not resolvable from the access token");
                    return Mono.empty();
                })
                .defaultIfEmpty(UNKNOWN);
    }
}
