package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.RequesterKind;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RequesterResolverTest {

    private static final String ORG = "VATES-A15456585";

    @Mock
    private CallerProvider callerProvider;

    private Mono<Requester> resolve(Map<String, Object> claims, String tenant) {
        Jwt jwt = new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "ES256"), claims);
        return new RequesterResolver(callerProvider).current()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt)))
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
    }

    private void caller(String credentialType) {
        when(callerProvider.current()).thenReturn(Mono.just(new Caller(ORG, List.of(), "sandbox", credentialType, "jti")));
    }

    @Test
    void aMachineAttestation_isASystemOfItsOrganization_whicheverWayTheTokenNamesItsType() {
        when(callerProvider.currentPerson()).thenReturn(Mono.just("did:key:machine-1"));
        for (String type : List.of("learcredential.machine.sd.1", "LEARCredentialMachine")) {
            caller(type);

            StepVerifier.create(resolve(Map.of("sub", "machine"), "sandbox"))
                    .assertNext(requester -> {
                        assertThat(requester.kind()).isEqualTo(RequesterKind.SYSTEM);
                        assertThat(requester.organizationIdentifier()).isEqualTo(ORG);
                        assertThat(requester.callerKey()).hasSize(64).doesNotContain("machine-1");
                    })
                    .verifyComplete();
        }
    }

    @Test
    void twoSystemsOfOneOrganization_shareTheCount_butNotTheIdempotencyKeys() {
        caller("learcredential.machine.sd.1");
        when(callerProvider.currentPerson()).thenReturn(Mono.just("did:key:machine-1"));
        Requester first = resolve(Map.of("sub", "m1"), "sandbox").block();
        when(callerProvider.currentPerson()).thenReturn(Mono.just("did:key:machine-2"));
        Requester second = resolve(Map.of("sub", "m2"), "sandbox").block();

        assertThat(first).isNotNull();
        assertThat(second).isNotNull();
        assertThat(first.countingScope()).isEqualTo(second.countingScope());
        assertThat(first.idempotencyScope()).isNotEqualTo(second.idempotencyScope());
    }

    @Test
    void anEmployeeAttestation_isAPerson_keptOnlyAsATenantScopedPseudonym() {
        caller("learcredential.employee.sd.1");
        when(callerProvider.currentPerson()).thenReturn(Mono.just(" Ana@Example.org "));

        Requester sandbox = resolve(Map.of("sub", "x"), "sandbox").block();
        Requester cgcom = resolve(Map.of("sub", "x"), "cgcom").block();

        assertThat(sandbox).isNotNull();
        assertThat(sandbox.kind()).isEqualTo(RequesterKind.PERSON);
        assertThat(sandbox.callerKey()).hasSize(64).doesNotContainIgnoringCase("ana");
        assertThat(cgcom).isNotNull();
        assertThat(cgcom.callerKey()).isNotEqualTo(sandbox.callerKey());
        // Case and surrounding spaces do not make another person.
        when(callerProvider.currentPerson()).thenReturn(Mono.just("ana@example.org"));
        assertThat(resolve(Map.of("sub", "x"), "sandbox").block()).isEqualTo(sandbox);
    }

    @Test
    void aPersonTheTokenDoesNotName_sharesOneCountWithinItsOrganization() {
        caller("learcredential.employee.sd.1");
        when(callerProvider.currentPerson()).thenReturn(Mono.empty());

        StepVerifier.create(resolve(Map.of("sub", "x"), "sandbox"))
                .assertNext(requester -> assertThat(requester.kind()).isEqualTo(RequesterKind.PERSON))
                .verifyComplete();
    }

    @Test
    void aTokenWithoutOrganization_orNoTokenAtAll_hasNoRequester() {
        when(callerProvider.current()).thenReturn(Mono.error(new InvalidTokenException("no organization")));

        StepVerifier.create(resolve(Map.of("sub", "x"), "sandbox")).verifyComplete();
        StepVerifier.create(new RequesterResolver(callerProvider).current()).verifyComplete();
    }
}
