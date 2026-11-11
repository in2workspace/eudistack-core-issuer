package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.util.RecipientPseudonymizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Locale;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Who sends the current request, for the volume limits and the idempotency (EUD-269), read only from the
 * access token the security layer already verified:
 * <ul>
 *   <li>the organization is the one of the {@link Caller} (its mandator);</li>
 *   <li>a system is a token of a LEAR machine attestation ({@code credential_type}
 *       {@code learcredential.machine.*}) or of the M2M intake ({@code caller_type} {@code M2M}); any other
 *       token is a person;</li>
 *   <li>a person is kept only as a pseudonym scoped to the tenant (as {@link RecipientPseudonymizer} does for
 *       the audit), never in clear.</li>
 * </ul>
 * Empty when the request has no verified token naming an organization: such a request is not counted, and
 * is rejected downstream on its own merits.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RequesterResolver {

    static final String MACHINE_CREDENTIAL_TYPE_PREFIX = "learcredential.machine";
    static final String CALLER_TYPE_CLAIM = "caller_type";
    static final String M2M_CALLER_TYPE = "M2M";
    /** Pseudonym input of a person the token does not name: all of them share one count. */
    static final String UNIDENTIFIED_PERSON = "<unidentified>";

    private final CallerProvider callerProvider;
    private final RecipientPseudonymizer pseudonymizer = new RecipientPseudonymizer();

    public Mono<Requester> current() {
        return claims()
                .flatMap(claims -> callerProvider.current()
                        .flatMap(caller -> isSystem(claims, caller)
                                ? Mono.just(Requester.system(caller.organizationIdentifier()))
                                : person(caller.organizationIdentifier())))
                .onErrorResume(e -> {
                    log.debug("No requester for the volume limit and the idempotency: {}", e.toString());
                    return Mono.empty();
                });
    }

    private Mono<Map<String, Object>> claims() {
        return ReactiveSecurityContextHolder.getContext()
                .mapNotNull(ctx -> ctx.getAuthentication())
                .filter(JwtAuthenticationToken.class::isInstance)
                .map(auth -> ((JwtAuthenticationToken) auth).getToken().getClaims());
    }

    static boolean isSystem(Map<String, Object> claims, Caller caller) {
        if (M2M_CALLER_TYPE.equals(claims.get(CALLER_TYPE_CLAIM))) {
            return true;
        }
        String credentialType = caller.credentialType();
        return credentialType != null
                && credentialType.toLowerCase(Locale.ROOT).startsWith(MACHINE_CREDENTIAL_TYPE_PREFIX);
    }

    private Mono<Requester> person(String organizationIdentifier) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            String scope = tenant.isBlank() ? "-" : tenant;
            return callerProvider.currentPerson()
                    .map(person -> person.trim().toLowerCase(Locale.ROOT))
                    .defaultIfEmpty(UNIDENTIFIED_PERSON)
                    .map(person -> Requester.person(organizationIdentifier, pseudonymizer.hash(scope, person)));
        });
    }
}
