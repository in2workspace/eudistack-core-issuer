package es.in2.issuer.backend.oidc4vci.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.*;
import reactor.core.publisher.Mono;

public interface Oid4VciCredentialWorkflow {

    Mono<CredentialResponse> generateVerifiableCredentialResponse(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext
    );

    Mono<CredentialResponse> generateVerifiableCredentialDeferredResponse(
            String processId,
            DeferredCredentialRequest deferredCredentialRequest,
            AccessTokenContext accessTokenContext
    );

    Mono<Void> bindAccessTokenByPreAuthorizedCode(
            String processId,
            AuthServerNonceRequest authServerNonceRequest
    );

}
