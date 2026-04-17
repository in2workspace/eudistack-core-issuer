package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

public interface IssuanceService {
    Mono<Issuance> saveIssuance(Issuance issuance);

    Mono<String> getCredentialTypeByIssuanceId(String issuanceId);

    Mono<String> getCredentialStatusByIssuanceId(String issuanceId);

    Mono<Void> updateCredentialDataSetByIssuanceId(String issuanceId, String credentialDataSet, String format);

    Mono<String> getCredentialDataSetByIssuanceId(String issuanceId);

    Flux<String> getAllIssuedCredentialByOrganizationIdentifier(String organizationIdentifier);

    Mono<IssuanceList> getAllIssuancesVisibleFor(AuthorizationContext ctx);

    Mono<IssuanceList> getAllIssuanceSummariesByOrganizationId(String organizationIdentifier);

    Mono<CredentialDetails> getIssuanceDetailByIssuanceIdAndOrganizationId(AuthorizationContext ctx, String issuanceId);

    Mono<Void> updateIssuanceStatusToValidByIssuanceId(String issuanceId);

    Mono<Void> updateIssuanceStatusToRevoked(Issuance issuance);

    Mono<Issuance> getIssuanceById(String issuanceId);

    Mono<Issuance> getIssuanceByCredentialOfferRefreshToken(String credentialOfferRefreshToken);

    Mono<JsonNode> extractCredentialNode(Issuance issuance);

    Mono<String> extractCredentialId(Issuance issuance);

    Mono<CredentialOfferEmailNotificationInfo> findCredentialOfferEmailInfoByIssuanceId(String issuanceId);

    Mono<Void> withdrawIssuance(String issuanceId);

    Flux<Issuance> findIssuedReadyForActivation(Instant now);

    Flux<Issuance> findStaleDrafts(Instant cutoff);

    Mono<Issuance> updateIssuance(Issuance issuance);

    Flux<Issuance> findFailedDeliveries(Instant cutoff);
}
