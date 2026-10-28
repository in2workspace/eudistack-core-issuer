package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.util.TenantIdentifiers;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.BEARER_PREFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccessTokenServiceImpl implements AccessTokenService {

    private final ObjectMapper objectMapper;
    private final IssuerProperties appConfig;
    private final TenantRegistryService tenantRegistryService;
    private final CallerProvider callerProvider;
    private final PowerAuthorizationService powerAuthorizationService;

    private static final String DPOP_PREFIX = "DPoP ";

    @Override
    public Mono<String> getCleanBearerToken(String authorizationHeader) {
        return Mono.just(authorizationHeader)
                .map(header -> {
                    if (header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                        return header.substring(BEARER_PREFIX.length()).trim();
                    }
                    if (header.regionMatches(true, 0, DPOP_PREFIX, 0, DPOP_PREFIX.length())) {
                        return header.substring(DPOP_PREFIX.length()).trim();
                    }
                    return header;
                });
    }

    @Override
    public Mono<String> getOrganizationId(String authorizationHeader) {
        return getCleanBearerToken(authorizationHeader)
                .flatMap(this::extractOrganizationIdFromToken)
                .switchIfEmpty(Mono.error(new InvalidTokenException()));
    }

    /**
     * The caller's role in the request's tenant, recognized from its powers by the single decision
     * point (EUD-253 FR-03) -- no tenant configuration takes part. Read-only for the platform
     * administrator in the {@code platform} tenant.
     */
    @Override
    public Mono<AuthorizationContext> getAuthorizationContext(String authorizationHeader) {
        return Mono.deferContextual(ctx -> {
            String currentTenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");

            return getCleanBearerToken(authorizationHeader)
                    .flatMap(callerProvider::fromToken)
                    .flatMap(powerAuthorizationService::recognize)
                    .flatMap(recognized -> tenantRegistryService.getTenantType(currentTenant)
                            .map(tenantType -> new AuthorizationContext(
                                    recognized.organizationIdentifier(),
                                    UserRole.fromUserType(recognized.userType()),
                                    recognized.readOnly(),
                                    tenantType)))
                    .switchIfEmpty(Mono.error(new InvalidTokenException()));
        });
    }

    @Override
    public Mono<String> getTokenTenant(String authorizationHeader) {
        return getCleanBearerToken(authorizationHeader)
                .flatMap(token -> Mono.fromCallable(() -> {
                    JsonNode root = parseTokenPayload(token);
                    JsonNode tenantNode = root.get("tenant");
                    String tenant = tenantNode != null && !tenantNode.isNull() ? tenantNode.asText() : null;
                    return TenantIdentifiers.stripEnvSuffix(tenant);
                }).onErrorMap(e -> e instanceof InvalidTokenException ? e : new InvalidTokenException()));
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

                                    String cnfJkt = extractCnfJkt(payload);
                                    return Mono.just(new AccessTokenContext(rawToken, jti, issuanceId, cnfJkt));
                                })
                );
    }

    // --- Private helpers ---

    // DPoP-bound access tokens (RFC 9449) carry cnf.jkt - the thumbprint of the key the
    // token is sender-constrained to. Absent for tokens that are not DPoP-bound (DPoP not required
    // for the issuing tenant profile).
    private String extractCnfJkt(Map<String, Object> payload) {
        Object cnf = payload.get("cnf");
        if (cnf instanceof Map<?, ?> cnfMap) {
            Object jkt = cnfMap.get("jkt");
            return jkt instanceof String jktStr ? jktStr : null;
        }
        return null;
    }

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

    private Mono<String> getTokenFromCurrentSession() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> {
                    JwtAuthenticationToken token = (JwtAuthenticationToken) ctx.getAuthentication();
                    return token.getToken().getTokenValue();
                });
    }
}
