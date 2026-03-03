package es.in2.issuer.backend.oidc4vci.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "oid4vci.profile")
public record Oid4vciProfileProperties(
        List<String> grantsSupported,
        AuthorizationCodeProperties authorizationCode
) {

    public record AuthorizationCodeProperties(
            boolean requirePar,
            boolean requirePkce,
            List<String> pkceMethods,
            boolean requireDpop,
            List<String> dpopSigningAlgs,
            String clientAuthMethod,
            boolean requireNonce
    ) {
        public AuthorizationCodeProperties {
            if (pkceMethods == null) pkceMethods = List.of("S256");
            if (dpopSigningAlgs == null) dpopSigningAlgs = List.of("ES256");
            if (clientAuthMethod == null) clientAuthMethod = "none";
        }
    }

    public Oid4vciProfileProperties {
        if (grantsSupported == null) grantsSupported = List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        if (authorizationCode == null) authorizationCode = new AuthorizationCodeProperties(
                false, false, List.of("S256"), false, List.of("ES256"), "none", false
        );
    }

    public boolean isAuthorizationCodeEnabled() {
        return grantsSupported != null && grantsSupported.contains("authorization_code");
    }

    public boolean isPreAuthorizedCodeEnabled() {
        return grantsSupported != null &&
                grantsSupported.contains("urn:ietf:params:oauth:grant-type:pre-authorized_code");
    }

    public boolean isHaipProfile() {
        return authorizationCode != null
                && authorizationCode.requirePar()
                && authorizationCode.requireDpop()
                && "attest_jwt_client_auth".equals(authorizationCode.clientAuthMethod());
    }
}
