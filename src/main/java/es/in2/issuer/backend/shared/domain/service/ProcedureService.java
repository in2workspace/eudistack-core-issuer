package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedures;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

public interface ProcedureService {
    Mono<CredentialProcedure> createCredentialProcedure(CredentialProcedureCreationRequest credentialProcedureCreationRequest);

    Mono<String> getCredentialTypeByProcedureId(String procedureId);

    Mono<String> getCredentialStatusByProcedureId(String procedureId);

    Mono<Void> updateCredentialDataSetByProcedureId(String procedureId, String credentialDataSet, String format);

    Mono<String> getCredentialDataSetByProcedureId(String procedureId);

    Flux<String> getAllIssuedCredentialByOrganizationIdentifier(String organizationIdentifier);

    Mono<CredentialProcedures> getAllProceduresVisibleFor(String organizationIdentifier, boolean sysAdmin);

    Mono<CredentialProcedures> getAllProceduresBasicInfoByOrganizationId(String organizationIdentifier);

    Mono<CredentialDetails> getProcedureDetailByProcedureIdAndOrganizationId(String organizationIdentifier, String procedureId, boolean sysAdmin);

    Mono<Void> updateCredentialProcedureCredentialStatusToValidByProcedureId(String procedureId);

    Mono<Void> updateCredentialProcedureCredentialStatusToRevoke(CredentialProcedure credentialProcedure);

    Mono<CredentialProcedure> getProcedureById(String procedureId);

    Mono<CredentialProcedure> getProcedureByCredentialOfferRefreshToken(String credentialOfferRefreshToken);

    Mono<JsonNode> extractCredentialNode(CredentialProcedure credentialProcedure);

    Mono<String> extractCredentialId(CredentialProcedure credentialProcedure);

    Mono<CredentialOfferEmailNotificationInfo> findCredentialOfferEmailInfoByProcedureId(String procedureId);

    Mono<Void> withdrawCredentialProcedure(String procedureId);

    Flux<CredentialProcedure> findIssuedReadyForActivation(Instant now);

    Flux<CredentialProcedure> findStaleDrafts(Instant cutoff);

    Mono<CredentialProcedure> updateProcedure(CredentialProcedure procedure);
}
