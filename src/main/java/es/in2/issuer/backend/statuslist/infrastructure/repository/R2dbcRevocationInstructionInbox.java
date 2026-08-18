package es.in2.issuer.backend.statuslist.infrastructure.repository;

import es.in2.issuer.backend.statuslist.domain.spi.RevocationInstructionInbox;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

/**
 * R2DBC adapter for {@link RevocationInstructionInbox} (AD-4). Tenant-scoped via
 * {@code search_path} like every other repository in this bounded context — the
 * caller is responsible for the {@code TENANT_DOMAIN_CONTEXT_KEY} being set in the
 * Reactor {@link reactor.util.context.Context} before subscribing.
 * <p>
 * The claim lease window (how long an {@code IN_PROGRESS} row is considered live
 * before a redelivery is allowed to re-claim it, NFR-S-225-04) is a fixed constant:
 * a proposed threshold pending team confirmation (spec-deltas.md SD-01), exposed
 * here rather than as a Spring property because — unlike the queue topology
 * properties in {@code RevocationMessagingConfig} — it is not part of the message
 * contract and has no other consumer today.
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public class R2dbcRevocationInstructionInbox implements RevocationInstructionInbox {

    private static final Duration CLAIM_LEASE_WINDOW = Duration.ofSeconds(60);

    private static final String STATUS_IN_PROGRESS = "IN_PROGRESS";
    private static final String STATUS_PROCESSED = "PROCESSED";
    private static final String STATUS_SKIPPED = "SKIPPED";

    private final DatabaseClient databaseClient;

    private record ExistingClaim(String status, Instant claimedAt) { }

    @Override
    public Mono<ClaimResult> claim(String messageId, String issuanceId) {
        requireNonNullParam(messageId, "messageId");
        requireNonNullParam(issuanceId, "issuanceId");

        return insertIfAbsent(messageId, issuanceId)
                .flatMap(claimed -> claimed
                        ? Mono.just(ClaimResult.CLAIMED)
                        : resolveExistingClaim(messageId, issuanceId))
                .doOnNext(result -> log.debug(
                        "method=claim step=END messageId={} result={}", messageId, result));
    }

    private Mono<Boolean> insertIfAbsent(String messageId, String issuanceId) {
        return databaseClient.sql("""
                        INSERT INTO revocation_instruction_inbox (message_id, issuance_id, status, claimed_at, attempts)
                        VALUES (:messageId, :issuanceId, :status, now(), 1)
                        ON CONFLICT (message_id) DO NOTHING
                        """)
                .bind("messageId", messageId)
                .bind("issuanceId", UUID.fromString(issuanceId))
                .bind("status", STATUS_IN_PROGRESS)
                .fetch()
                .rowsUpdated()
                .map(rows -> rows != null && rows > 0);
    }

    private Mono<ClaimResult> resolveExistingClaim(String messageId, String issuanceId) {
        Instant leaseThreshold = Instant.now().minus(CLAIM_LEASE_WINDOW);

        return readStatus(messageId)
                .flatMap(existing -> {
                    if (!STATUS_IN_PROGRESS.equals(existing.status())) {
                        return Mono.just(ClaimResult.ALREADY_PROCESSED);
                    }
                    if (!existing.claimedAt().isBefore(leaseThreshold)) {
                        return Mono.just(ClaimResult.IN_PROGRESS);
                    }
                    return reclaimExpired(messageId, issuanceId, leaseThreshold);
                })
                // Copilot (EUD-225 PR review): readStatus's .one() completes empty, not an
                // error, when zero rows match -- reachable if a concurrent release() (a
                // sibling replica retrying the same redelivered message, AC-09) deletes the
                // IN_PROGRESS row between this method's failed INSERT and this SELECT. Without
                // this, claim() would itself complete empty (no ClaimResult, no error), and the
                // caller could treat a dropped instruction as silently handled. The row being
                // gone now is exactly the precondition a fresh claim() already knows how to
                // handle -- retrying it is not a special case, it's the same insert-or-resolve
                // logic re-entered from the top.
                .switchIfEmpty(Mono.defer(() -> claim(messageId, issuanceId)));
    }

    private Mono<ClaimResult> reclaimExpired(String messageId, String issuanceId, Instant leaseThreshold) {
        return databaseClient.sql("""
                        UPDATE revocation_instruction_inbox
                        SET claimed_at = now(), attempts = attempts + 1
                        WHERE message_id = :messageId AND status = :status AND claimed_at < :leaseThreshold
                        """)
                .bind("messageId", messageId)
                .bind("status", STATUS_IN_PROGRESS)
                .bind("leaseThreshold", leaseThreshold)
                .fetch()
                .rowsUpdated()
                .flatMap(rows -> (rows != null && rows > 0)
                        ? Mono.just(ClaimResult.CLAIMED)
                        // Lost the race for the expired lease to a concurrent re-claim; the
                        // winner has already moved the row on, so re-read its outcome.
                        : resolveExistingClaim(messageId, issuanceId));
    }

    private Mono<ExistingClaim> readStatus(String messageId) {
        return databaseClient.sql("SELECT status, claimed_at FROM revocation_instruction_inbox WHERE message_id = :messageId")
                .bind("messageId", messageId)
                .map((row, metadata) -> new ExistingClaim(
                        row.get("status", String.class),
                        row.get("claimed_at", Instant.class)
                ))
                .one();
    }

    @Override
    public Mono<Void> markProcessed(String messageId) {
        return updateTerminalStatus(messageId, STATUS_PROCESSED);
    }

    @Override
    public Mono<Void> markSkipped(String messageId) {
        return updateTerminalStatus(messageId, STATUS_SKIPPED);
    }

    @Override
    public Mono<Void> release(String messageId) {
        requireNonNullParam(messageId, "messageId");
        // Restricted to IN_PROGRESS: never deletes a row another attempt already closed
        // (PROCESSED/SKIPPED) out from under a late caller.
        return databaseClient.sql("""
                        DELETE FROM revocation_instruction_inbox
                        WHERE message_id = :messageId AND status = :status
                        """)
                .bind("messageId", messageId)
                .bind("status", STATUS_IN_PROGRESS)
                .fetch()
                .rowsUpdated()
                .doOnNext(rows -> log.debug(
                        "method=release messageId={} rowsDeleted={}", messageId, rows))
                .then();
    }

    private Mono<Void> updateTerminalStatus(String messageId, String status) {
        requireNonNullParam(messageId, "messageId");
        return databaseClient.sql("""
                        UPDATE revocation_instruction_inbox
                        SET status = :status, processed_at = now()
                        WHERE message_id = :messageId
                        """)
                .bind("messageId", messageId)
                .bind("status", status)
                .fetch()
                .rowsUpdated()
                .doOnNext(rows -> log.debug(
                        "method=updateTerminalStatus messageId={} status={} rowsUpdated={}", messageId, status, rows))
                .then();
    }
}
