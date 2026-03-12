package es.in2.issuer.backend.oidc4vci.domain.model.port;

import java.util.List;

public interface Oid4vciProfilePort {

    List<String> grantsSupported();

    AuthorizationCodeConfig authorizationCode();

    boolean isAuthorizationCodeEnabled();

    boolean isPreAuthorizedCodeEnabled();

    boolean isHaipProfile();

    interface AuthorizationCodeConfig {
        boolean requirePar();
        boolean requirePkce();
        List<String> pkceMethods();
        boolean requireDpop();
        List<String> dpopSigningAlgs();
        String clientAuthMethod();
        boolean requireNonce();
    }
}
