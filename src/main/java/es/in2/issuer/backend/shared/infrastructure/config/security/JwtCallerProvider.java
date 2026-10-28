package es.in2.issuer.backend.shared.infrastructure.config.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.policy.Caller;
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
 * attestation type: no credential profile says where the powers are (point 16). The organization
 * is read at {@code app.management-token.org-id-json-path}, like every other management call.
 *
 * <p>A token without the organization it represents is not a caller of the management API: it is
 * rejected as an invalid token (401) rather than decided with a null organization.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtCallerProvider implements CallerProvider {

    private static final String POWER_CLAIM = "power";

    private final ObjectMapper objectMapper;
    private final IssuerProperties issuerProperties;

    @Override
    public Mono<Caller> current() {
        return ReactiveSecurityContextHolder.getContext()
                .mapNotNull(ctx -> ctx.getAuthentication())
                .filter(JwtAuthenticationToken.class::isInstance)
                .map(auth -> ((JwtAuthenticationToken) auth).getToken().getTokenValue())
                .switchIfEmpty(Mono.error(new InvalidTokenException("No authenticated caller")))
                .flatMap(this::fromToken);
    }

    @Override
    public Mono<Caller> fromToken(String token) {
        return Mono.fromCallable(() -> parse(token))
                .onErrorMap(e -> e instanceof InvalidTokenException ? e : new InvalidTokenException());
    }

    private Caller parse(String token) throws Exception {
        JsonNode root = objectMapper.readTree(SignedJWT.parse(token).getPayload().toString());
        String organization = text(at(root, issuerProperties.getManagementTokenOrgIdJsonPath()));
        if (organization == null || organization.isBlank()) {
            throw new InvalidTokenException("The access token names no organization");
        }
        return new Caller(
                organization,
                powers(root.path(POWER_CLAIM)),
                TenantIdentifiers.stripEnvSuffix(text(root.path("tenant"))),
                text(root.path("credential_type")),
                text(root.path("jti")),
                attestationId(root.path("vc")));
    }

    /**
     * The attestation the caller authenticated with (AC-16, FR-13): its {@code id} (W3C) or, for an
     * SD-JWT VC, which has none, its entry in the status list -- unique per issued attestation and
     * free of personal data.
     */
    private static String attestationId(JsonNode vc) {
        String id = text(vc.path("id"));
        if (id != null) {
            return id;
        }
        JsonNode entry = vc.path("status").path("status_list");
        String uri = text(entry.path("uri"));
        String index = text(entry.path("idx"));
        return uri != null && index != null ? uri + "#" + index : null;
    }

    private static JsonNode at(JsonNode root, String dottedPath) {
        JsonNode node = root;
        for (String segment : dottedPath.split("\\.")) {
            node = node.path(segment);
        }
        return node;
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
