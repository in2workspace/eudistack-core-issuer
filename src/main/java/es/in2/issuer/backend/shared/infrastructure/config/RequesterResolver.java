package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.util.RecipientPseudonymizer;
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
 *   <li>the organization is the one of the {@link Caller} (its mandator);</li>
 *   <li>a system is a token of a LEAR machine attestation ({@link Caller#isSystem()}, the same rule as the
 *       authorization by powers); any other token is a person;</li>
 *   <li>the person or the system is kept only as a pseudonym scoped to the tenant (as
 *       {@link RecipientPseudonymizer} does for the audit), never in clear.</li>
 * </ul>
 * Empty when the request has no verified token naming an organization (among them the M2M intake tokens,
 * which name none and are not allowed on these APIs): such a request is not counted, and is rejected
 * downstream on its own merits.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RequesterResolver {

    /** Pseudonym input of a person the token does not name: all of them share one count. */
    static final String UNIDENTIFIED_PERSON = "<unidentified>";

    private final CallerProvider callerProvider;
    private final RecipientPseudonymizer pseudonymizer = new RecipientPseudonymizer();

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
            String scope = tenant.isBlank() ? "-" : tenant;
            return callerProvider.currentPerson()
                    .map(who -> pseudonymizer.hash(scope, who.trim().toLowerCase(Locale.ROOT)))
                    .map(Optional::of)
                    .defaultIfEmpty(Optional.empty())
                    .map(callerKey -> caller.isSystem()
                            ? Requester.system(caller.organizationIdentifier(), callerKey.orElse(null))
                            : Requester.person(caller.organizationIdentifier(),
                                    callerKey.orElseGet(() -> pseudonymizer.hash(scope, UNIDENTIFIED_PERSON))));
        });
    }
}
