package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.OrgContext;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;

import static es.in2.issuer.backend.shared.domain.util.Constants.BEARER_PREFIX;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccessTokenServiceImpl implements AccessTokenService {

    private final ObjectMapper objectMapper;
    private final IssuerProperties appConfig;

    @Override
    public Mono<String> getCleanBearerToken(String authorizationHeader) {
        return Mono.just(authorizationHeader)
                .map(header -> header.startsWith(BEARER_PREFIX)
                        ? header.substring(BEARER_PREFIX.length()).trim()
                        : header);
    }

    @Override
    public Mono<String> getOrganizationId(String authorizationHeader) {
        return getCleanBearerToken(authorizationHeader)
                .flatMap(this::extractOrganizationIdFromToken)
                .switchIfEmpty(Mono.error(new InvalidTokenException()));
    }

    @Override
    public Mono<OrgContext> getOrganizationContext(String authorizationHeader) {
        String orgIdPath = appConfig.getManagementTokenOrgIdJsonPath();
        String adminPowerFunction = appConfig.getManagementTokenAdminPowerFunction();
        String adminPowerAction = appConfig.getManagementTokenAdminPowerAction();

        return getCleanBearerToken(authorizationHeader)
                .flatMap(token -> Mono.fromCallable(() -> {
                    JsonNode root = parseTokenPayload(token);
                    String orgId = resolveJsonPath(root, orgIdPath);
                    if (orgId == null) {
                        throw new InvalidTokenException("Organization ID not found at path: " + orgIdPath);
                    }
                    boolean isSysAdmin = orgId.equals(appConfig.getAdminOrganizationId())
                            && hasPowerInPayload(root, adminPowerFunction, adminPowerAction);
                    return new OrgContext(orgId, isSysAdmin);
                }).onErrorMap(e -> e instanceof InvalidTokenException ? e : new InvalidTokenException()))
                .switchIfEmpty(Mono.error(new InvalidTokenException()));
    }

    @Override
    public Mono<String> getOrganizationIdFromCurrentSession() {
        return getTokenFromCurrentSession()
                .flatMap(this::getCleanBearerToken)
                .flatMap(this::extractOrganizationIdFromToken)
                .switchIfEmpty(Mono.error(new InvalidTokenException()));
    }

    @Override
    public Mono<AccessTokenContext> resolveAccessTokenContext(String authorizationHeader) {
        return getCleanBearerToken(authorizationHeader)
                .flatMap(rawToken ->
                        Mono.fromCallable(() -> JWSObject.parse(rawToken))
                                .onErrorMap(e -> new InvalidTokenException("Error parsing access token"))
                                .flatMap(jws -> {
                                    var payload = jws.getPayload().toJSONObject();

                                    String jti = (String) payload.get("jti");
                                    String issuanceId = (String) payload.get("pid");
                                    Number expValue = (Number) payload.get("exp");

                                    if (jti == null || jti.isBlank())
                                        return Mono.error(new InvalidTokenException("Access token without jti"));
                                    if (issuanceId == null || issuanceId.isBlank())
                                        return Mono.error(new InvalidTokenException("Access token without pid"));
                                    if (expValue == null)
                                        return Mono.error(new InvalidTokenException("Access token without exp"));
                                    if (Instant.ofEpochSecond(expValue.longValue()).isBefore(Instant.now()))
                                        return Mono.error(new InvalidTokenException("Access token expired"));

                                    return Mono.just(new AccessTokenContext(rawToken, jti, issuanceId));
                                })
                );
    }

    // --- Private helpers ---

    private Mono<String> extractOrganizationIdFromToken(String token) {
        String orgIdPath = appConfig.getManagementTokenOrgIdJsonPath();
        return Mono.fromCallable(() -> {
            JsonNode root = parseTokenPayload(token);
            String value = resolveJsonPath(root, orgIdPath);
            if (value == null) {
                throw new InvalidTokenException("Organization ID not found at path: " + orgIdPath);
            }
            return value;
        }).onErrorMap(e -> e instanceof InvalidTokenException ? e : new InvalidTokenException());
    }

    private JsonNode parseTokenPayload(String token) throws Exception {
        SignedJWT parsedJwt = SignedJWT.parse(token);
        return objectMapper.readTree(parsedJwt.getPayload().toString());
    }

    /**
     * Navigates a dot-separated JSON path (e.g. "vc.credentialSubject.mandate.mandator.organizationIdentifier")
     * and returns the text value at the leaf, or null if any segment is missing.
     */
    private String resolveJsonPath(JsonNode root, String dotPath) {
        JsonNode current = root;
        for (String segment : dotPath.split("\\.")) {
            if (current == null || current.isMissingNode() || current.isNull()) {
                return null;
            }
            current = current.get(segment);
        }
        return (current != null && !current.isMissingNode() && !current.isNull())
                ? current.asText()
                : null;
    }

    /**
     * Searches for a power entry with the given function and action in the token payload.
     * Looks for the "power" array at the path derived from the org-id path's parent (mandate level).
     */
    private boolean hasPowerInPayload(JsonNode root, String function, String action) {
        // Navigate to the parent of the org-id path to find the mandate-level node containing "power"
        String orgIdPath = appConfig.getManagementTokenOrgIdJsonPath();
        String[] segments = orgIdPath.split("\\.");

        // Walk up two levels from the org-id leaf to reach the mandate-level node
        // e.g. from "vc.credentialSubject.mandate.mandator.organizationIdentifier"
        //   → go to "vc.credentialSubject.mandate" (remove last 2 segments)
        JsonNode mandateNode = root;
        int mandateDepth = Math.max(0, segments.length - 2);
        for (int i = 0; i < mandateDepth; i++) {
            if (mandateNode == null) return false;
            mandateNode = mandateNode.get(segments[i]);
        }
        if (mandateNode == null) return false;

        JsonNode powerNode = mandateNode.get("power");
        if (powerNode == null || !powerNode.isArray()) {
            return false;
        }
        for (JsonNode power : powerNode) {
            if (matchesPowerFunction(power, function)) {
                JsonNode actionNode = power.has("action") ? power.get("action") : power.get("tmf_action");
                if (actionNode != null && matchesAction(actionNode, action)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean matchesPowerFunction(JsonNode power, String function) {
        return function.equals(power.path("function").asText(null))
                || function.equals(power.path("tmf_function").asText(null));
    }

    private boolean matchesAction(JsonNode actionNode, String action) {
        if (actionNode.isTextual()) {
            return action.equals(actionNode.asText());
        } else if (actionNode.isArray()) {
            for (JsonNode a : actionNode) {
                if (action.equals(a.asText())) {
                    return true;
                }
            }
        }
        return false;
    }

    private Mono<String> getTokenFromCurrentSession() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> {
                    JwtAuthenticationToken token = (JwtAuthenticationToken) ctx.getAuthentication();
                    return token.getToken().getTokenValue();
                });
    }
}
