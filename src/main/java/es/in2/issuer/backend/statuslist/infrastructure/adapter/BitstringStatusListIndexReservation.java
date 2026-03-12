package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import es.in2.issuer.backend.statuslist.domain.exception.IndexReservationExhaustedException;
import es.in2.issuer.backend.statuslist.domain.model.StatusListIndexData;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListIndexAllocator;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListIndexReservation;
import es.in2.issuer.backend.statuslist.domain.spi.UniqueViolationClassifier;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndexRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.CAPACITY_BITS;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@Slf4j
@Service
@RequiredArgsConstructor
public class BitstringStatusListIndexReservation implements StatusListIndexReservation {

    private final StatusListIndexRepository statusListIndexRepository;
    private final StatusListIndexAllocator indexAllocator;
    private final UniqueViolationClassifier uniqueViolationClassifier;

    @Override
    public Mono<StatusListIndexData> reserve(Long statusListId, String issuanceId) {
        return reserveWithRetry(statusListId, issuanceId)
                .map(BitstringStatusListIndexReservation::toDomain);
    }

    private static final long MAX_ATTEMPTS = 15;
    private static final long EARLY_ESCAPE_AFTER = 8;
    private static final double EARLY_ESCAPE_FILL_RATIO = 0.95;

    private Mono<StatusListIndex> reserveWithRetry(Long statusListId, String issuanceId) {
        log.info("reserveOnSpecificList - statusListId: {} - issuanceId: {}", statusListId, issuanceId);
        requireNonNullParam(statusListId, "statusListId");
        requireNonNullParam(issuanceId, "issuanceId");

        return Mono.defer(() -> tryReserveOnce(statusListId, issuanceId))
                .retryWhen(
                        Retry.backoff(MAX_ATTEMPTS - 1L, Duration.ofMillis(5))
                                .maxBackoff(Duration.ofMillis(100))
                                .filter(t -> {
                                    UniqueViolationClassifier.Kind k = uniqueViolationClassifier.classify(t);
                                    return k == UniqueViolationClassifier.Kind.IDX || k == UniqueViolationClassifier.Kind.UNKNOWN;
                                })
                                .doBeforeRetry(rs -> {
                                    long attempt = rs.totalRetries() + 2;
                                    log.debug(
                                            "action=reserveStatusListIndex retryReason=uniqueCollision statusListId={} issuanceId={} attempt={}/{}",
                                        statusListId, issuanceId, attempt, MAX_ATTEMPTS
                                );
                                })
                )
                .onErrorResume(t -> earlyEscapeIfNearlyFull(t, statusListId))
                .onErrorMap(this::maybeWrapAsExhausted);
    }

    /**
     * After exhausting retries, check if the list is nearly full (>95%).
     * If so, immediately signal exhaustion instead of retrying further.
     */
    private Mono<StatusListIndex> earlyEscapeIfNearlyFull(Throwable t, Long statusListId) {
        UniqueViolationClassifier.Kind k = uniqueViolationClassifier.classify(t);
        if (k != UniqueViolationClassifier.Kind.IDX && k != UniqueViolationClassifier.Kind.UNKNOWN) {
            return Mono.error(t);
        }

        return statusListIndexRepository.countByStatusListId(statusListId)
                .flatMap(count -> {
                    double fillRatio = (double) count / CAPACITY_BITS;
                    if (fillRatio >= EARLY_ESCAPE_FILL_RATIO) {
                        log.info("action=earlyEscape statusListId={} fillRatio={} count={}", statusListId, fillRatio, count);
                        return Mono.error(new IndexReservationExhaustedException(
                                "List nearly full (%.1f%%), skipping to new list".formatted(fillRatio * 100), t));
                    }
                    return Mono.error(t);
                });
    }

    private Mono<StatusListIndex> tryReserveOnce(Long statusListId, String issuanceId) {
        int idx = indexAllocator.proposeIndex(CAPACITY_BITS);

        StatusListIndex row = new StatusListIndex(
                null,
                statusListId,
                idx,
                UUID.fromString(issuanceId),
                Instant.now()
        );

        return statusListIndexRepository.save(row)
                .doOnNext(saved -> log.debug(
                        "Saved StatusListIndex: id={}, statusListId={}, idx={}, issuanceId={}, createdAt={}",
                        saved.id(),
                        saved.statusListId(),
                        saved.idx(),
                        saved.issuanceId(),
                        saved.createdAt()
                ))
                .onErrorResume(t -> {
                    UniqueViolationClassifier.Kind k = uniqueViolationClassifier.classify(t);
                    log.debug(
                            "action=tryReserveOnce constraintKind={} statusListId={} idx={} issuanceId={}",
                            k, statusListId, idx, issuanceId
                    );

                    if (k == UniqueViolationClassifier.Kind.ISSUANCE_ID) {
                        return statusListIndexRepository.findByIssuanceId(UUID.fromString(issuanceId))
                                .switchIfEmpty(Mono.error(t));
                    }

                    // For IDX/UNKNOWN we want the retryWhen to handle it; for NOT_UNIQUE we fail fast.
                    return Mono.error(t);
                });

    }

    private Throwable maybeWrapAsExhausted(Throwable t) {
        UniqueViolationClassifier.Kind k = uniqueViolationClassifier.classify(t);
        if (k == UniqueViolationClassifier.Kind.IDX || k == UniqueViolationClassifier.Kind.UNKNOWN) {
            return new IndexReservationExhaustedException("Too many collisions while reserving index", t);
        }
        return t;
    }

    private static StatusListIndexData toDomain(StatusListIndex entity) {
        return new StatusListIndexData(
                entity.id(),
                entity.statusListId(),
                entity.idx(),
                entity.issuanceId(),
                entity.createdAt()
        );
    }

}

