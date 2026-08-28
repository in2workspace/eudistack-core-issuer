package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface IssuanceRepository extends ReactiveCrudRepository<Issuance, UUID> {
    Flux<Issuance> findByCredentialStatusAndOrganizationIdentifier(CredentialStatusEnum credentialStatusEnum, String organizationIdentifier);
    @Query("SELECT * FROM issuance WHERE organization_identifier = :organizationIdentifier ORDER BY updated_at DESC")
    Flux<Issuance> findAllByOrganizationIdentifier(String organizationIdentifier);
    @Query("SELECT * FROM issuance ORDER BY updated_at DESC")
    Flux<Issuance> findAllOrderByUpdatedDesc();
    Mono<Issuance> findByIssuanceIdAndOrganizationIdentifier(UUID issuanceId, String organizationIdentifier);
    @Query("SELECT credential_status FROM issuance WHERE issuance_id = :issuanceId")
    Mono<String> findCredentialStatusByIssuanceId(UUID issuanceId);
    Mono<Issuance> findByIssuanceId(UUID issuanceId);
    Mono<Issuance> findByCredentialOfferRefreshToken(String credentialOfferRefreshToken);
    Flux<Issuance> findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum credentialStatus, Instant cutoff);

    @Query("SELECT * FROM issuance WHERE credential_status = :status AND (valid_from IS NULL OR valid_from <= :now)")
    Flux<Issuance> findIssuedReadyForActivation(CredentialStatusEnum status, Instant now);

    @Query("SELECT * FROM issuance WHERE credential_status = 'DRAFT' AND delivery_attempted_at IS NOT NULL AND delivery_attempted_at < :cutoff")
    Flux<Issuance> findFailedDeliveries(Instant cutoff);
}
