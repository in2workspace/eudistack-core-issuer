package es.in2.issuer.backend.issuance.application.workflow;

import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import reactor.core.publisher.Mono;

public interface IssuanceWorkflow {

    Mono<IssuanceResponse> issueCredential(String processId, IssuanceRequest request, String idToken,
                                           String publicIssuerBaseUrl);

    Mono<IssuanceResponse> issueCredentialWithoutAuthorization(String processId, IssuanceRequest request,
                                                               String publicIssuerBaseUrl);

}
