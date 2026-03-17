package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.HashMap;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RequireCertificationIssuanceRuleTest {

    @Mock
    private VerifierService verifierService;
    @Mock
    private JWTService jwtService;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private DynamicCredentialParser credentialParser;

    private RequireCertificationIssuanceRule rule;

    @BeforeEach
    void setUp() {
        rule = new RequireCertificationIssuanceRule(verifierService, jwtService, objectMapper, credentialParser);
    }

    private List<Power> buildPowers(String function, String action) {
        return List.of(Power.builder().function(function).action(action).build());
    }

    @Test
    void evaluate_succeedsWhenBothSignerAndIdTokenHaveCertificationAttest() throws Exception {
        List<Power> signerPowers = buildPowers("Certification", "Attest");
        PolicyContext ctx = new PolicyContext("Org", signerPowers, null, null, "learcredential.machine.w3c.3", false, null, null);

        String idToken = "dummy-id-token";

        SignedJWT idTokenJWT = mock(SignedJWT.class);
        Payload idTokenPayload = new Payload(new HashMap<>());
        when(idTokenJWT.getPayload()).thenReturn(idTokenPayload);
        when(verifierService.verifyTokenWithoutExpiration(idToken)).thenReturn(Mono.empty());
        when(jwtService.parseJWT(idToken)).thenReturn(idTokenJWT);
        when(jwtService.getClaimFromPayload(idTokenPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");

        com.fasterxml.jackson.databind.node.ObjectNode idTokenVcNode = new ObjectMapper().createObjectNode();
        CredentialProfile idTokenProfile = mock(CredentialProfile.class);
        Power idTokenPower = Power.builder().function("Certification").action("Attest").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(idTokenVcNode, idTokenProfile, "learcredential.employee.w3c.4");
        when(credentialParser.parse("vcJson")).thenReturn(parsed);
        when(credentialParser.extractPowers(idTokenVcNode, idTokenProfile)).thenReturn(List.of(idTokenPower));

        StepVerifier.create(rule.evaluate(ctx, idToken))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenSignerLacksCertificationPower() {
        List<Power> signerPowers = buildPowers("Onboarding", "Execute");
        PolicyContext ctx = new PolicyContext("Org", signerPowers, null, null, "learcredential.machine.w3c.3", false, null, null);

        StepVerifier.create(rule.evaluate(ctx, "dummy-id-token"))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Signer credential does not have Certification/Attest power"))
                .verify();
    }

    @Test
    void evaluate_failsWhenIdTokenLacksCertificationPower() throws Exception {
        List<Power> signerPowers = buildPowers("Certification", "Attest");
        PolicyContext ctx = new PolicyContext("Org", signerPowers, null, null, "learcredential.machine.w3c.3", false, null, null);

        String idToken = "dummy-id-token";

        SignedJWT idTokenJWT = mock(SignedJWT.class);
        Payload idTokenPayload = new Payload(new HashMap<>());
        when(idTokenJWT.getPayload()).thenReturn(idTokenPayload);
        when(verifierService.verifyTokenWithoutExpiration(idToken)).thenReturn(Mono.empty());
        when(jwtService.parseJWT(idToken)).thenReturn(idTokenJWT);
        when(jwtService.getClaimFromPayload(idTokenPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");

        com.fasterxml.jackson.databind.node.ObjectNode idTokenVcNode = new ObjectMapper().createObjectNode();
        CredentialProfile idTokenProfile = mock(CredentialProfile.class);
        Power idTokenPower = Power.builder().function("Onboarding").action("Execute").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(idTokenVcNode, idTokenProfile, "learcredential.employee.w3c.4");
        when(credentialParser.parse("vcJson")).thenReturn(parsed);
        when(credentialParser.extractPowers(idTokenVcNode, idTokenProfile)).thenReturn(List.of(idTokenPower));

        StepVerifier.create(rule.evaluate(ctx, idToken))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("ID token credential does not have Certification/Attest power"))
                .verify();
    }
}
