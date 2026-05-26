package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import com.nimbusds.jose.jwk.JWKSet;
import es.in2.issuer.backend.dome.infrastructure.adapter.keys.DomeJwkProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.JWKS_PATH;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final DomeJwkProvider domeJwkProvider;

    @GetMapping(value = JWKS_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<Map<String, Object>> getJwks() {
        return domeJwkProvider.resolvePublicJwks().map(JWKSet::toJSONObject);
    }
}
