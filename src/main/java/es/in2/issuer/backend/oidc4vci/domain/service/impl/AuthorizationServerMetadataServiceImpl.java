package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationServerMetadata;
import es.in2.issuer.backend.oidc4vci.domain.service.AuthorizationServerMetadataService;
import es.in2.issuer.backend.oidc4vci.infrastructure.config.Oid4vciProfileProperties;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationServerMetadataServiceImpl implements AuthorizationServerMetadataService {

    private final AppConfig appConfig;
    private final Oid4vciProfileProperties profileProperties;

    @Override
    public Mono<AuthorizationServerMetadata> buildAuthorizationServerMetadata(String processId) {
        String issuerUrl = appConfig.getIssuerBackendUrl();
        boolean authCodeEnabled = profileProperties.isAuthorizationCodeEnabled();
        var authCodeConfig = profileProperties.authorizationCode();

        Set<String> responseTypes = new HashSet<>();
        responseTypes.add("token");
        if (authCodeEnabled) {
            responseTypes.add("code");
        }

        Set<String> grantTypes = new HashSet<>(profileProperties.grantsSupported());

        var builder = AuthorizationServerMetadata.builder()
                .issuer(issuerUrl)
                .tokenEndpoint(issuerUrl + OAUTH_TOKEN_PATH)
                .jwksUri(issuerUrl + JWKS_PATH)
                .responseTypesSupported(responseTypes)
                .preAuthorizedGrantAnonymousAccessSupported(profileProperties.isPreAuthorizedCodeEnabled())
                .grantTypesSupported(grantTypes);

        if (authCodeEnabled) {
            builder.authorizationEndpoint(issuerUrl + OID4VCI_AUTHORIZE_PATH);
            builder.tokenEndpointAuthMethodsSupported(List.of(authCodeConfig.clientAuthMethod()));

            if (authCodeConfig.requirePkce()) {
                builder.codeChallengeMethodsSupported(authCodeConfig.pkceMethods());
            }

            if (authCodeConfig.requirePar()) {
                builder.pushedAuthorizationRequestEndpoint(issuerUrl + OID4VCI_PAR_PATH);
                builder.requirePushedAuthorizationRequests(true);
            }

            if (authCodeConfig.requireDpop()) {
                builder.dpopSigningAlgValuesSupported(authCodeConfig.dpopSigningAlgs());
            }

            if (authCodeConfig.requireNonce()) {
                builder.nonceEndpoint(issuerUrl + OID4VCI_NONCE_PATH);
            }

            builder.authorizationResponseIssParameterSupported(true);
        }

        return Mono.just(builder.build());
    }
}