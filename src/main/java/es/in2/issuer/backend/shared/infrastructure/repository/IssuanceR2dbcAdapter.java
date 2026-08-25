package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.shared.infrastructure.persistence.IssuanceMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * R2DBC adapter for {@link IssuancePort} (EUDISTACK-650 / H-05). Same pattern as
 * {@code ApiClientRepositoryAdapter}: talks R2DBC/{@code IssuanceEntity} here, hands the
 * domain only {@link Issuance}.
 */
@Component
@RequiredArgsConstructor
public class IssuanceR2dbcAdapter implements IssuancePort {

    private final IssuanceR2dbcRepository issuanceR2dbcRepository;
    private final R2dbcEntityTemplate r2dbcEntityTemplate;

    @Override
    public Mono<Issuance> insert(Issuance issuance) {
        return r2dbcEntityTemplate.insert(IssuanceMapper.toEntity(issuance))
                .map(IssuanceMapper::toDomain);
    }

    @Override
    public Mono<Issuance> findById(UUID issuanceId) {
        return issuanceR2dbcRepository.findById(issuanceId).map(IssuanceMapper::toDomain);
    }

    @Override
    public Flux<Issuance> findAll() {
        return issuanceR2dbcRepository.findAll().map(IssuanceMapper::toDomain);
    }

    @Override
    public Mono<Issuance> save(Issuance issuance) {
        return issuanceR2dbcRepository.save(IssuanceMapper.toEntity(issuance)).map(IssuanceMapper::toDomain);
    }

    @Override
    public Flux<Issuance> findByCredentialStatusAndOrganizationIdentifier(CredentialStatusEnum credentialStatus, String organizationIdentifier) {
        return issuanceR2dbcRepository.findByCredentialStatusAndOrganizationIdentifier(credentialStatus, organizationIdentifier)
                .map(IssuanceMapper::toDomain);
    }

    @Override
    public Flux<Issuance> findAllByOrganizationIdentifier(String organizationIdentifier) {
        return issuanceR2dbcRepository.findAllByOrganizationIdentifier(organizationIdentifier)
                .map(IssuanceMapper::toDomain);
    }

    @Override
    public Flux<Issuance> findAllOrderByUpdatedDesc() {
        return issuanceR2dbcRepository.findAllOrderByUpdatedDesc().map(IssuanceMapper::toDomain);
    }

    @Override
    public Mono<Issuance> findByIssuanceIdAndOrganizationIdentifier(UUID issuanceId, String organizationIdentifier) {
        return issuanceR2dbcRepository.findByIssuanceIdAndOrganizationIdentifier(issuanceId, organizationIdentifier)
                .map(IssuanceMapper::toDomain);
    }

    @Override
    public Mono<String> findCredentialStatusByIssuanceId(UUID issuanceId) {
        return issuanceR2dbcRepository.findCredentialStatusByIssuanceId(issuanceId);
    }

    @Override
    public Mono<Issuance> findByIssuanceId(UUID issuanceId) {
        return issuanceR2dbcRepository.findByIssuanceId(issuanceId).map(IssuanceMapper::toDomain);
    }

    @Override
    public Mono<Issuance> findByCredentialOfferRefreshToken(String credentialOfferRefreshToken) {
        return issuanceR2dbcRepository.findByCredentialOfferRefreshToken(credentialOfferRefreshToken)
                .map(IssuanceMapper::toDomain);
    }

    @Override
    public Flux<Issuance> findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum credentialStatus, Instant cutoff) {
        return issuanceR2dbcRepository.findByCredentialStatusAndCreatedAtBefore(credentialStatus, cutoff)
                .map(IssuanceMapper::toDomain);
    }

    @Override
    public Flux<Issuance> findIssuedReadyForActivation(CredentialStatusEnum status, Instant now) {
        return issuanceR2dbcRepository.findIssuedReadyForActivation(status, now).map(IssuanceMapper::toDomain);
    }

    @Override
    public Flux<Issuance> findFailedDeliveries(Instant cutoff) {
        return issuanceR2dbcRepository.findFailedDeliveries(cutoff).map(IssuanceMapper::toDomain);
    }
}
