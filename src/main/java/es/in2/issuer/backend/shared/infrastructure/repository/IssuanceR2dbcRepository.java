package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.infrastructure.persistence.IssuanceEntity;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface IssuanceR2dbcRepository extends ReactiveCrudRepository<IssuanceEntity, UUID> {
    Flux<IssuanceEntity> findByCredentialStatusAndOrganizationIdentifier(CredentialStatusEnum credentialStatusEnum, String organizationIdentifier);
    @Query("SELECT * FROM issuance WHERE organization_identifier = :organizationIdentifier ORDER BY updated_at DESC")
    Flux<IssuanceEntity> findAllByOrganizationIdentifier(String organizationIdentifier);
    @Query("SELECT * FROM issuance ORDER BY updated_at DESC")
    Flux<IssuanceEntity> findAllOrderByUpdatedDesc();
    Mono<IssuanceEntity> findByIssuanceIdAndOrganizationIdentifier(UUID issuanceId, String organizationIdentifier);
    @Query("SELECT credential_status FROM issuance WHERE issuance_id = :issuanceId")
    Mono<String> findCredentialStatusByIssuanceId(UUID issuanceId);
    Mono<IssuanceEntity> findByIssuanceId(UUID issuanceId);
    Mono<IssuanceEntity> findByCredentialOfferRefreshToken(String credentialOfferRefreshToken);
    Flux<IssuanceEntity> findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum credentialStatus, Instant cutoff);

    @Query("SELECT * FROM issuance WHERE credential_status = :status AND (valid_from IS NULL OR valid_from <= :now)")
    Flux<IssuanceEntity> findIssuedReadyForActivation(CredentialStatusEnum status, Instant now);

    @Query("SELECT * FROM issuance WHERE credential_status = 'DRAFT' AND delivery_attempted_at IS NOT NULL AND delivery_attempted_at < :cutoff")
    Flux<IssuanceEntity> findFailedDeliveries(Instant cutoff);
}
