package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.util.TenantIdentifiers;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Builds the {@link Caller} from the access token. The verifier puts the mandate of the LEAR
 * attestation (employee or machine) in flat claims -- {@code mandator}, {@code power},
 * {@code credential_type}, {@code tenant} -- and they are read here directly, the same for every
 * attestation type: no credential profile says where the powers are (point 16).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CallerResolver {

    private static final String POWER_CLAIM = "power";
    private static final String MANDATOR_CLAIM = "mandator";
    private static final String ORG_ID_FIELD = "organizationIdentifier";

    private final ObjectMapper objectMapper;

    /** Caller of the current request, from the token Spring Security already validated. */
    public Mono<Caller> fromSecurityContext() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ((JwtAuthenticationToken) ctx.getAuthentication()).getToken().getTokenValue())
                .switchIfEmpty(Mono.error(new InvalidTokenException("No authenticated caller")))
                .flatMap(this::fromToken);
    }

    public Mono<Caller> fromToken(String token) {
        return Mono.fromCallable(() -> parse(token))
                .onErrorMap(e -> e instanceof InvalidTokenException ? e : new InvalidTokenException());
    }

    private Caller parse(String token) throws Exception {
        JsonNode root = objectMapper.readTree(SignedJWT.parse(token).getPayload().toString());
        return new Caller(
                text(root.path(MANDATOR_CLAIM).path(ORG_ID_FIELD)),
                powers(root.path(POWER_CLAIM)),
                TenantIdentifiers.stripEnvSuffix(text(root.path("tenant"))),
                text(root.path("credential_type")),
                text(root.path("sub")),
                text(root.path("jti")),
                text(root.path("vc").path("id")));
    }

    private List<Power> powers(JsonNode node) {
        if (!node.isArray()) {
            return List.of();
        }
        try {
            return objectMapper.convertValue(node, new TypeReference<>() {});
        } catch (IllegalArgumentException e) {
            log.debug("Unreadable power claim: {}", e.getMessage());
            return List.of();
        }
    }

    private static String text(JsonNode node) {
        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }
}
