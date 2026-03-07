package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.IssuanceCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import reactor.core.publisher.Mono;

public interface CredentialDataSetBuilderService {

    Mono<IssuanceCreationRequest> buildDataSet(
            String issuanceId,
            PreSubmittedCredentialDataRequest request
    );

}
