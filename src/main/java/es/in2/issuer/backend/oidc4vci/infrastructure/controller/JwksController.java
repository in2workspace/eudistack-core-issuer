package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.JWKS_PATH;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final ECKey ecKey;

    @GetMapping(value = JWKS_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getJwks() {
        JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
        return jwkSet.toJSONObject();
    }
}
