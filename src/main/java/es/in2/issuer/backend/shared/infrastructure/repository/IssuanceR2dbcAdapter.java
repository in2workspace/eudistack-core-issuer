package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.exception.ConcurrentIssuanceUpdateException;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.shared.infrastructure.persistence.IssuanceEntity;
import es.in2.issuer.backend.shared.infrastructure.persistence.IssuanceMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
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
                .map(IssuanceMapper::toDomain)
                .onErrorMap(OptimisticLockingFailureException.class,
                        e -> new ConcurrentIssuanceUpdateException(issuance.getIssuanceId(), "insert", e));
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
        return issuanceR2dbcRepository.save(IssuanceMapper.toEntity(issuance))
                .map(IssuanceMapper::toDomain)
                .onErrorMap(OptimisticLockingFailureException.class,
                        e -> new ConcurrentIssuanceUpdateException(issuance.getIssuanceId(), "save", e));
    }

    @Override
    public Flux<Issuance> findByCredentialStatusAndOrganizationIdentifier(CredentialStatusEnum credentialStatus, String organizationIdentifier) {
        return issuanceR2dbcRepository.findByCredentialStatusAndOrganizationIdentifier(credentialStatus, organizationIdentifier)
                .map(IssuanceMapper::toDomain);
    }

    /**
     * Keyset pagination (EUD-255 AD-1) with the row comparison {@code (last_changed_at, issuance_id) <
     * cursor}, which the indexes of V20 serve in the order of the {@code ORDER BY}. Every value is a
     * bind parameter; only the shape of the statement depends on which filters are present.
     */
    @Override
    public Flux<Issuance> findPage(IssuanceQuery query, String organizationIdentifier, int fetchSize) {
        StringBuilder sql = new StringBuilder("SELECT * FROM issuance WHERE TRUE");
        Map<String, Object> binds = new LinkedHashMap<>();
        if (organizationIdentifier != null) {
            sql.append(" AND organization_identifier = :organizationIdentifier");
            binds.put("organizationIdentifier", organizationIdentifier);
        }
        if (!query.lifeCycleStatuses().isEmpty()) {
            sql.append(" AND credential_status IN (:lifeCycleStatuses)");
            binds.put("lifeCycleStatuses", query.lifeCycleStatuses().stream().map(Enum::name).sorted().toList());
        }
        if (query.credentialConfigurationId() != null) {
            // The catalogue entry is stored in credential_type (EUD-255 §5 of the prd).
            sql.append(" AND credential_type = :credentialConfigurationId");
            binds.put("credentialConfigurationId", query.credentialConfigurationId());
        }
        if (query.cursor() != null) {
            sql.append(" AND (last_changed_at, issuance_id) < (CAST(:afterLastChangedAt AS timestamptz), CAST(:afterIssuanceId AS uuid))");
            binds.put("afterLastChangedAt", query.cursor().position().lastChangedAt());
            binds.put("afterIssuanceId", query.cursor().position().issuanceId());
        }
        sql.append(" ORDER BY last_changed_at DESC, issuance_id DESC LIMIT :fetchSize");
        binds.put("fetchSize", fetchSize);

        DatabaseClient.GenericExecuteSpec spec = r2dbcEntityTemplate.getDatabaseClient().sql(sql.toString());
        for (Map.Entry<String, Object> bind : binds.entrySet()) {
            spec = spec.bind(bind.getKey(), bind.getValue());
        }
        return spec.map((row, metadata) -> r2dbcEntityTemplate.getConverter().read(IssuanceEntity.class, row, metadata))
                .all()
                .map(IssuanceMapper::toDomain);
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
