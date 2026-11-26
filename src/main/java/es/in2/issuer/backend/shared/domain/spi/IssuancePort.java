package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
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

    /**
     * One page of the listing in the current tenant (EUD-255 AD-1): the processes that match the
     * query's filters and come after its cursor, newest last change first, at most {@code fetchSize}.
     * The tenant filter of the query is not applied here: the caller picks the schema. A search by
     * identifier must come fingerprinted (EUD-255 AD-5); one with its value in clear fails.
     *
     * @param organizationIdentifier only that organization's processes, or {@code null} for the whole tenant
     */
    Flux<Issuance> findPage(IssuanceQuery query, String organizationIdentifier, int fetchSize);

    Mono<Issuance> findByIssuanceIdAndOrganizationIdentifier(UUID issuanceId, String organizationIdentifier);

    Mono<String> findCredentialStatusByIssuanceId(UUID issuanceId);

    Mono<Issuance> findByIssuanceId(UUID issuanceId);

    Mono<Issuance> findByCredentialOfferRefreshToken(String credentialOfferRefreshToken);

    Flux<Issuance> findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum credentialStatus, Instant cutoff);

    Flux<Issuance> findIssuedReadyForActivation(CredentialStatusEnum status, Instant now);

    Flux<Issuance> findFailedDeliveries(Instant cutoff);
}
