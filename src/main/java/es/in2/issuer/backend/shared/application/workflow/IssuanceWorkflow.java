package es.in2.issuer.backend.shared.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import reactor.core.publisher.Mono;

public interface IssuanceWorkflow {

    Mono<IssuanceResponse> execute(String processId, PreSubmittedCredentialDataRequest request, String idToken);

    Mono<IssuanceResponse> executeWithoutAuthorization(String processId, PreSubmittedCredentialDataRequest request);

}
