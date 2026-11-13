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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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
        caller(credentialType, "sandbox", null);
    }

    private void caller(String credentialType, String tokenTenant, String attestationId) {
        when(callerProvider.current()).thenReturn(Mono.just(
                new Caller(ORG, List.of(), tokenTenant, credentialType, "jti", attestationId)));
    }

    @Test
    void aMachineAttestation_isASystemOfItsOrganization_namedByItsSub_whicheverWayTheTokenNamesItsType() {
        when(callerProvider.currentSubject()).thenReturn(Mono.just("did:key:machine-1"));
        for (String type : List.of("learcredential.machine.sd.1", "LEARCredentialMachine")) {
            caller(type);

            StepVerifier.create(resolve(Map.of("sub", "machine"), "sandbox"))
                    .assertNext(requester -> {
                        assertThat(requester.kind()).isEqualTo(RequesterKind.SYSTEM);
                        assertThat(requester.organizationIdentifier()).isEqualTo(ORG);
                        assertThat(requester.tenant()).isEqualTo("sandbox");
                        assertThat(requester.callerKey()).hasSize(64).doesNotContain("machine-1");
                    })
                    .verifyComplete();
        }
        verify(callerProvider, never()).currentPerson();
    }

    @Test
    void aSystem_isNamedByItsAttestationBeforeItsSub_neverByAnEmail() {
        caller("learcredential.machine.sd.1", "sandbox", "https://issuer/status/1#7");
        Requester byAttestation = resolve(Map.of("sub", "m"), "sandbox").block();
        caller("learcredential.machine.sd.1", "sandbox", "https://issuer/status/1#8");
        Requester otherAttestation = resolve(Map.of("sub", "m"), "sandbox").block();

        assertThat(byAttestation).isNotNull();
        assertThat(otherAttestation).isNotNull();
        assertThat(byAttestation.idempotencyScope()).isNotEqualTo(otherAttestation.idempotencyScope());
        verify(callerProvider, never()).currentSubject();
        verify(callerProvider, never()).currentPerson();
    }

    @Test
    void aSystemTheTokenDoesNotName_isCounted_butHasNoIdempotencyScope() {
        caller("learcredential.machine.sd.1");
        when(callerProvider.currentSubject()).thenReturn(Mono.empty());

        StepVerifier.create(resolve(Map.of("iss", "verifier"), "sandbox"))
                .assertNext(requester -> {
                    assertThat(requester.kind()).isEqualTo(RequesterKind.SYSTEM);
                    assertThat(requester.idempotencyScope()).isEmpty();
                })
                .verifyComplete();
    }

    @Test
    void twoSystemsOfOneOrganization_shareTheCount_butNotTheIdempotencyKeys() {
        caller("learcredential.machine.sd.1");
        when(callerProvider.currentSubject()).thenReturn(Mono.just("did:key:machine-1"));
        Requester first = resolve(Map.of("sub", "m1"), "sandbox").block();
        when(callerProvider.currentSubject()).thenReturn(Mono.just("did:key:machine-2"));
        Requester second = resolve(Map.of("sub", "m2"), "sandbox").block();

        assertThat(first).isNotNull();
        assertThat(second).isNotNull();
        assertThat(first.countingScope()).isEqualTo(second.countingScope());
        assertThat(first.idempotencyScope()).isNotEqualTo(second.idempotencyScope());
    }

    @Test
    void anEmployeeAttestation_isAPerson_keptOnlyAsATenantScopedPseudonym() {
        when(callerProvider.currentPerson()).thenReturn(Mono.just(" Ana@Example.org "));

        caller("learcredential.employee.sd.1", "sandbox", null);
        Requester sandbox = resolve(Map.of("sub", "x"), "sandbox").block();
        caller("learcredential.employee.sd.1", "cgcom", null);
        Requester cgcom = resolve(Map.of("sub", "x"), "cgcom").block();

        assertThat(sandbox).isNotNull();
        assertThat(sandbox.kind()).isEqualTo(RequesterKind.PERSON);
        assertThat(sandbox.callerKey()).hasSize(64).doesNotContainIgnoringCase("ana");
        assertThat(cgcom).isNotNull();
        assertThat(cgcom.callerKey()).isNotEqualTo(sandbox.callerKey());
        // Case and surrounding spaces do not make another person.
        caller("learcredential.employee.sd.1", "sandbox", null);
        when(callerProvider.currentPerson()).thenReturn(Mono.just("ana@example.org"));
        assertThat(resolve(Map.of("sub", "x"), "sandbox").block()).isEqualTo(sandbox);
    }

    @Test
    void aPersonTheTokenDoesNotName_isCountedWithinItsOrganization_butHasNoIdempotencyScope() {
        caller("learcredential.employee.sd.1");
        when(callerProvider.currentPerson()).thenReturn(Mono.empty());

        StepVerifier.create(resolve(Map.of("sub", "x"), "sandbox"))
                .assertNext(requester -> {
                    assertThat(requester.kind()).isEqualTo(RequesterKind.PERSON);
                    assertThat(requester.idempotencyScope()).isEmpty();
                })
                .verifyComplete();
    }

    @Test
    void aTokenOfAnotherTenant_orWithoutTenant_hasNoRequester_soItTouchesNothingOfTheRequestedTenant() {
        caller("learcredential.employee.sd.1", "tenant-a", null);
        StepVerifier.create(resolve(Map.of("sub", "x"), "tenant-b")).verifyComplete();

        caller("learcredential.employee.sd.1", null, null);
        StepVerifier.create(resolve(Map.of("sub", "x"), "tenant-b")).verifyComplete();

        caller("learcredential.employee.sd.1", "tenant-b", null);
        StepVerifier.create(resolve(Map.of("sub", "x"), " ")).verifyComplete();
        verify(callerProvider, never()).currentPerson();
    }

    @Test
    void theTenantIsComparedWithoutCase() {
        caller("learcredential.employee.sd.1", "Sandbox", null);
        when(callerProvider.currentPerson()).thenReturn(Mono.just("ana@example.org"));

        StepVerifier.create(resolve(Map.of("sub", "x"), "sandbox"))
                .assertNext(requester -> assertThat(requester.tenant()).isEqualTo("sandbox"))
                .verifyComplete();
    }

    @Test
    void aTokenWithoutOrganization_orNoTokenAtAll_hasNoRequester() {
        when(callerProvider.current()).thenReturn(Mono.error(new InvalidTokenException("no organization")));

        StepVerifier.create(resolve(Map.of("sub", "x"), "sandbox")).verifyComplete();
        StepVerifier.create(new RequesterResolver(callerProvider).current()).verifyComplete();
    }
}
