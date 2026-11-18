package es.in2.issuer.backend.shared.infrastructure.audit;

import es.in2.issuer.backend.shared.domain.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Who an access token says its caller is, for the actor of an audit event (AC-10).
 *
 * <p>It reads only the access token, which the security chain verified, and never the authentication
 * principal: the principal comes first from an {@code X-ID-Token} whose signature nobody checks, so whoever
 * sent one could name anybody as the actor. The order is the one the revocation trace uses: the email of the
 * mandatee, then the mandatee's own id (the DID of a system), then {@code client_id}, {@code sub},
 * {@code azp} and {@code jti}. {@code sub} comes late because a system's is the IP address its attestation
 * declares, which does not identify it.
 */
@Component
@RequiredArgsConstructor
public class AccessTokenActor {

    private static final String MANDATEE_CLAIM = "mandatee";
    private static final String EMAIL_FIELD = "email";
    private static final List<String> MANDATEE_FIELDS = List.of(EMAIL_FIELD, "id");
    private static final List<String> CALLER_CLAIMS = List.of("client_id", "sub", "azp", "jti");

    private final JWTService jwtService;

    /** The id of the caller, or empty when the token names none. */
    public Optional<String> idOf(Jwt token) {
        Map<String, Object> claims = token.getClaims();
        Map<?, ?> mandatee = claims.get(MANDATEE_CLAIM) instanceof Map<?, ?> map ? map : Map.of();
        List<Object> candidates = new ArrayList<>();
        candidates.add(jwtService.extractMandateeEmail(claims).orElse(null));
        MANDATEE_FIELDS.forEach(field -> candidates.add(mandatee.get(field)));
        CALLER_CLAIMS.forEach(claim -> candidates.add(claims.get(claim)));
        return firstText(candidates);
    }

    /** The email of the caller, when the token carries one. */
    public Optional<String> emailOf(Jwt token) {
        Map<String, Object> claims = token.getClaims();
        Map<?, ?> mandatee = claims.get(MANDATEE_CLAIM) instanceof Map<?, ?> map ? map : Map.of();
        List<Object> candidates = new ArrayList<>();
        candidates.add(jwtService.extractMandateeEmail(claims).orElse(null));
        candidates.add(mandatee.get(EMAIL_FIELD));
        candidates.add(claims.get(EMAIL_FIELD));
        return firstText(candidates);
    }

    private static Optional<String> firstText(List<Object> candidates) {
        return candidates.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(value -> !value.isBlank())
                .findFirst();
    }
}
