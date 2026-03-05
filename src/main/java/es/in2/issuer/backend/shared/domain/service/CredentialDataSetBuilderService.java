package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import reactor.core.publisher.Mono;

public interface CredentialDataSetBuilderService {

    Mono<CredentialProcedureCreationRequest> buildDataSet(
            String procedureId,
            PreSubmittedCredentialDataRequest request
    );

}
