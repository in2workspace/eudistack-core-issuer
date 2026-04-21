package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.model.dto.MeResponse;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ME_PATH;

/**
 * Exposes the authorization role of the current caller resolved against the
 * current tenant. Lets frontends render UI without knowing the tenant's
 * admin_organization_id (which lives in tenant_config and is backend-only).
 */
@RestController
@RequestMapping(ME_PATH)
@RequiredArgsConstructor
public class MeController {

    private final AccessTokenService accessTokenService;

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<MeResponse> getMe(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            return accessTokenService.getAuthorizationContext(authorizationHeader)
                    .map(auth -> new MeResponse(
                            auth.organizationIdentifier(),
                            auth.role(),
                            auth.readOnly(),
                            tenant
                    ));
        });
    }
}
