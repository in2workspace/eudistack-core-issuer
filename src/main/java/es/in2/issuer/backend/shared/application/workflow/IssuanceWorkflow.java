package es.in2.issuer.backend.shared.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import reactor.core.publisher.Mono;

public interface IssuanceWorkflow {

    Mono<IssuanceResponse> issueCredential(String processId, PreSubmittedCredentialDataRequest request, String idToken);

    Mono<IssuanceResponse> issueCredentialWithoutAuthorization(String processId, PreSubmittedCredentialDataRequest request);

}
