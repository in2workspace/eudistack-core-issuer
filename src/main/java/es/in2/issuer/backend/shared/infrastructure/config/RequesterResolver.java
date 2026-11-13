package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.util.Sha256;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Locale;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Who sends the current request, for the volume limits and the idempotency (EUD-269), read only from the
 * access token the security layer already verified:
 * <ul>
 *   <li>the token must have been issued for the tenant of the request ({@code X-Tenant}); otherwise there is
 *       no requester, so neither the counters nor the idempotency records of the tenant are touched, and
 *       the decision point answers 403 {@code tenant_mismatch} (conv-seguridad: one authorization point);</li>
 *   <li>the organization is the one of the {@link Caller} (its mandator);</li>
 *   <li>a system is a token of a LEAR machine attestation ({@link Caller#isSystem()}, the same rule as the
 *       authorization by powers), named by the id of its attestation or, without one, by the token's
 *       {@code sub} -- never by an email, which several systems of an organization may share; any other
 *       token is a person, named by the mandatee's email or the {@code sub};</li>
 *   <li>the person or the system is kept only as a digest scoped to the tenant, never in clear; what is stored
 *       of it (the counter key and the idempotency key) is an HMAC of that digest with the idempotency secret.</li>
 * </ul>
 * Empty when the request has no verified token naming an organization (among them the M2M intake tokens,
 * which name none and are not allowed on these APIs): such a request is not counted, and is rejected
 * downstream on its own merits.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RequesterResolver {

    private final CallerProvider callerProvider;

    public Mono<Requester> current() {
        return callerProvider.current()
                .flatMap(this::requester)
                .onErrorResume(e -> {
                    log.debug("No requester for the volume limit and the idempotency: {}", e.toString());
                    return Mono.empty();
                });
    }

    private Mono<Requester> requester(Caller caller) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            String tokenTenant = caller.tokenTenant();
            if (tenant.isBlank() || tokenTenant == null || !tokenTenant.equalsIgnoreCase(tenant)) {
                log.debug("No requester: the token was not issued for the tenant of the request");
                return Mono.empty();
            }
            String scope = tenant.toLowerCase(Locale.ROOT);
            return identifier(caller)
                    .map(who -> Sha256.hex(scope + "|" + who.trim().toLowerCase(Locale.ROOT)))
                    .map(Optional::of)
                    .defaultIfEmpty(Optional.empty())
                    .map(callerKey -> caller.isSystem()
                            ? Requester.system(scope, caller.organizationIdentifier(), callerKey.orElse(null))
                            : Requester.person(scope, caller.organizationIdentifier(), callerKey.orElse(null)));
        });
    }

    private Mono<String> identifier(Caller caller) {
        if (!caller.isSystem()) {
            return callerProvider.currentPerson();
        }
        String attestation = caller.attestationId();
        return attestation != null && !attestation.isBlank()
                ? Mono.just("attestation:" + attestation)
                : callerProvider.currentSubject().map(sub -> "sub:" + sub);
    }
}
