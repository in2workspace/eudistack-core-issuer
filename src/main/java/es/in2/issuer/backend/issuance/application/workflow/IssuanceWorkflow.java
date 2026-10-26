package es.in2.issuer.backend.issuance.application.workflow;

import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import reactor.core.publisher.Mono;

public interface IssuanceWorkflow {

    /**
     * Issues on behalf of the current caller once the power-based authorization permits it; the
     * process belongs to the organization that decision sets (EUD-253 FR-07).
     *
     * @param bearerToken the caller's {@code Authorization} header. The direct delivery mode signs
     *                    inside this request, so it needs a caller token of its own; the wallet modes
     *                    sign later, against their own OID4VCI access token, and ignore it.
     */
    Mono<IssuanceResponse> issueCredential(String processId, IssuanceRequest request,
                                           String bearerToken, String publicIssuerBaseUrl);

    Mono<IssuanceResponse> issueCredentialWithoutAuthorization(String processId, IssuanceRequest request, String token,
                                                               String publicIssuerBaseUrl);

}
