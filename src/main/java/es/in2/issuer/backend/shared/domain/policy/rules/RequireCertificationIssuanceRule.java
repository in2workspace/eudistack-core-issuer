package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Utils.extractPowers;

/**
 * Certification issuance policy for gx:LabelCredential.
 * T = String (the idToken).
 * Checks:
 * 1. Signer credential has Certification function + Attest action
 * 2. idToken is valid (signature verified) and also has Certification + Attest
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RequireCertificationIssuanceRule implements PolicyRule<String> {

    private final VerifierService verifierService;
    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final CredentialFactory credentialFactory;

    @Override
    public Mono<Void> evaluate(PolicyContext context, String idToken) {
        boolean signerValid = containsCertificationAndAttest(extractPowers(context.credential()));
        if (!signerValid) {
            return Mono.error(new InsufficientPermissionException(
                    "Signer credential does not have Certification/Attest power"));
        }

        return validateIdToken(idToken)
                .flatMap(idTokenPowers -> {
                    if (containsCertificationAndAttest(idTokenPowers)) {
                        return Mono.empty();
                    }
                    return Mono.error(new InsufficientPermissionException(
                            "ID token credential does not have Certification/Attest power"));
                });
    }

    private Mono<List<Power>> validateIdToken(String idToken) {
        return verifierService.verifyTokenWithoutExpiration(idToken)
                .then(Mono.fromCallable(() -> jwtService.parseJWT(idToken)))
                .flatMap(idSignedJWT -> {
                    String idVcClaim = jwtService.getClaimFromPayload(idSignedJWT.getPayload(), "vc_json");
                    try {
                        String processedVc = objectMapper.readValue(idVcClaim, String.class);
                        var credentialEmployee = credentialFactory.learCredentialEmployeeFactory
                                .mapStringToLEARCredentialEmployee(processedVc);
                        return Mono.just(extractPowers(credentialEmployee));
                    } catch (JsonProcessingException e) {
                        return Mono.error(new ParseErrorException("Error parsing id_token credential: " + e));
                    }
                });
    }

    private boolean containsCertificationAndAttest(List<Power> powers) {
        return powers.stream().anyMatch(p -> "Certification".equals(p.function()))
                && powers.stream().anyMatch(p -> PolicyContext.hasAction(p, "Attest"));
    }
}
