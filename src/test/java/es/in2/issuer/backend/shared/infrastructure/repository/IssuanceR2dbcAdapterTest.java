package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.infrastructure.persistence.IssuanceEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IssuanceR2dbcAdapterTest {

    @Mock
    private IssuanceR2dbcRepository issuanceR2dbcRepository;

    @Mock
    private R2dbcEntityTemplate r2dbcEntityTemplate;

    private IssuanceR2dbcAdapter adapter;

    private UUID issuanceId;
    private Issuance domainIssuance;
    private IssuanceEntity entity;

    @BeforeEach
    void setUp() {
        adapter = new IssuanceR2dbcAdapter(issuanceR2dbcRepository, r2dbcEntityTemplate);

        issuanceId = UUID.randomUUID();
        domainIssuance = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .organizationIdentifier("VATEU-B12345678")
                .build();
        entity = IssuanceEntity.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .organizationIdentifier("VATEU-B12345678")
                .build();
    }

    @Test
    void shouldInsertViaR2dbcEntityTemplateAndReturnMappedDomain() {
        when(r2dbcEntityTemplate.insert(any(IssuanceEntity.class))).thenReturn(Mono.just(entity));

        StepVerifier.create(adapter.insert(domainIssuance))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindByIdAndReturnMappedDomain() {
        when(issuanceR2dbcRepository.findById(issuanceId)).thenReturn(Mono.just(entity));

        StepVerifier.create(adapter.findById(issuanceId))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldReturnEmptyWhenFindByIdFindsNothing() {
        when(issuanceR2dbcRepository.findById(issuanceId)).thenReturn(Mono.empty());

        StepVerifier.create(adapter.findById(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindAllAndReturnMappedDomainFlux() {
        when(issuanceR2dbcRepository.findAll()).thenReturn(Flux.just(entity));

        StepVerifier.create(adapter.findAll())
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldSaveAndReturnMappedDomain() {
        when(issuanceR2dbcRepository.save(any(IssuanceEntity.class))).thenReturn(Mono.just(entity));

        StepVerifier.create(adapter.save(domainIssuance))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();

        verify(issuanceR2dbcRepository).save(any(IssuanceEntity.class));
    }

    @Test
    void shouldFindByCredentialStatusAndOrganizationIdentifier() {
        when(issuanceR2dbcRepository.findByCredentialStatusAndOrganizationIdentifier(
                CredentialStatusEnum.ISSUED, "VATEU-B12345678"))
                .thenReturn(Flux.just(entity));

        StepVerifier.create(adapter.findByCredentialStatusAndOrganizationIdentifier(
                        CredentialStatusEnum.ISSUED, "VATEU-B12345678"))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindAllByOrganizationIdentifier() {
        when(issuanceR2dbcRepository.findAllByOrganizationIdentifier("VATEU-B12345678"))
                .thenReturn(Flux.just(entity));

        StepVerifier.create(adapter.findAllByOrganizationIdentifier("VATEU-B12345678"))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindAllOrderByUpdatedDesc() {
        when(issuanceR2dbcRepository.findAllOrderByUpdatedDesc()).thenReturn(Flux.just(entity));

        StepVerifier.create(adapter.findAllOrderByUpdatedDesc())
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindByIssuanceIdAndOrganizationIdentifier() {
        when(issuanceR2dbcRepository.findByIssuanceIdAndOrganizationIdentifier(issuanceId, "VATEU-B12345678"))
                .thenReturn(Mono.just(entity));

        StepVerifier.create(adapter.findByIssuanceIdAndOrganizationIdentifier(issuanceId, "VATEU-B12345678"))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindCredentialStatusByIssuanceIdWithoutMapping() {
        when(issuanceR2dbcRepository.findCredentialStatusByIssuanceId(issuanceId))
                .thenReturn(Mono.just("ISSUED"));

        StepVerifier.create(adapter.findCredentialStatusByIssuanceId(issuanceId))
                .expectNext("ISSUED")
                .verifyComplete();
    }

    @Test
    void shouldFindByIssuanceId() {
        when(issuanceR2dbcRepository.findByIssuanceId(issuanceId)).thenReturn(Mono.just(entity));

        StepVerifier.create(adapter.findByIssuanceId(issuanceId))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindByCredentialOfferRefreshToken() {
        when(issuanceR2dbcRepository.findByCredentialOfferRefreshToken("refresh-token"))
                .thenReturn(Mono.just(entity));

        StepVerifier.create(adapter.findByCredentialOfferRefreshToken("refresh-token"))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindByCredentialStatusAndCreatedAtBefore() {
        Instant cutoff = Instant.now();
        when(issuanceR2dbcRepository.findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum.DRAFT, cutoff))
                .thenReturn(Flux.just(entity));

        StepVerifier.create(adapter.findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum.DRAFT, cutoff))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindIssuedReadyForActivation() {
        Instant now = Instant.now();
        when(issuanceR2dbcRepository.findIssuedReadyForActivation(eq(CredentialStatusEnum.ISSUED), any(Instant.class)))
                .thenReturn(Flux.just(entity));

        StepVerifier.create(adapter.findIssuedReadyForActivation(CredentialStatusEnum.ISSUED, now))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }

    @Test
    void shouldFindFailedDeliveries() {
        Instant cutoff = Instant.now();
        when(issuanceR2dbcRepository.findFailedDeliveries(cutoff)).thenReturn(Flux.just(entity));

        StepVerifier.create(adapter.findFailedDeliveries(cutoff))
                .expectNextMatches(result -> result.getIssuanceId().equals(issuanceId))
                .verifyComplete();
    }
}
