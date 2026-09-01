package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * Persistence port for {@link Issuance} (EUDISTACK-650 / H-05). The domain depends only on
 * this interface; {@code IssuanceR2dbcAdapter} (infrastructure) is the sole implementation.
 */
public interface IssuancePort {

    /**
     * Forces an INSERT of a brand-new issuance (never an upsert). Distinct from {@link #save},
     * mirroring the pre-refactor behavior of inserting via {@code R2dbcEntityTemplate} directly.
     */
    Mono<Issuance> insert(Issuance issuance);

    Mono<Issuance> findById(UUID issuanceId);

    Flux<Issuance> findAll();

    Mono<Issuance> save(Issuance issuance);

    Flux<Issuance> findByCredentialStatusAndOrganizationIdentifier(CredentialStatusEnum credentialStatus, String organizationIdentifier);

    Flux<Issuance> findAllByOrganizationIdentifier(String organizationIdentifier);

    Flux<Issuance> findAllOrderByUpdatedDesc();

    Mono<Issuance> findByIssuanceIdAndOrganizationIdentifier(UUID issuanceId, String organizationIdentifier);

    Mono<String> findCredentialStatusByIssuanceId(UUID issuanceId);

    Mono<Issuance> findByIssuanceId(UUID issuanceId);

    Mono<Issuance> findByCredentialOfferRefreshToken(String credentialOfferRefreshToken);

    Flux<Issuance> findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum credentialStatus, Instant cutoff);

    Flux<Issuance> findIssuedReadyForActivation(CredentialStatusEnum status, Instant now);

    Flux<Issuance> findFailedDeliveries(Instant cutoff);
}
