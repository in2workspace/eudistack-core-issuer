package es.in2.issuer.backend.oidc4vci.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialRequest;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialResponse;
import reactor.core.publisher.Mono;

public interface Oid4VciCredentialWorkflow {

    Mono<CredentialResponse> createCredentialResponse(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext
    );

}
