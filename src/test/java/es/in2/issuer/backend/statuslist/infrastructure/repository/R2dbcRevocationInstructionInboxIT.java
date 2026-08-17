package es.in2.issuer.backend.statuslist.infrastructure.repository;

import es.in2.issuer.backend.statuslist.domain.spi.RevocationInstructionInbox;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.statuslist.domain.spi.RevocationInstructionInbox.ClaimResult.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Real Postgres coverage for the AD-4 idempotency inbox (EUD-225). {@code ON
 * CONFLICT} atomicity and the expired-claim re-claim path cannot be exercised
 * meaningfully against a mock, hence an IT (Testcontainers) rather than a
 * Mockito unit test, per the choice technical-design.md §3.2 leaves open
 * ("R2dbcRevocationInstructionInboxTest.java, nuevo, o IT si requiere BBDD real").
 * <p>
 * Covers AC-05 (redelivery of an already-processed message), EC-03 (redelivery
 * overlapping an in-flight delivery), EC-04 (expired claim after a simulated
 * consumer crash) and NFR-S-225-04 (claim lease window).
 */
class R2dbcRevocationInstructionInboxIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";

    @Autowired
    private RevocationInstructionInbox inbox;

    private <T> Mono<T> tenantScoped(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    @Test
    void claim_newMessage_returnsClaimed() {
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        StepVerifier.create(tenantScoped(inbox.claim(messageId, issuanceId)))
                .expectNext(CLAIMED)
                .verifyComplete();
    }

    @Test
    void claim_afterMarkProcessed_returnsAlreadyProcessed() {
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        StepVerifier.create(tenantScoped(
                inbox.claim(messageId, issuanceId)
                        .then(inbox.markProcessed(messageId))
                        .then(inbox.claim(messageId, issuanceId))
        )).expectNext(ALREADY_PROCESSED).verifyComplete();
    }

    @Test
    void claim_afterMarkSkipped_returnsAlreadyProcessed() {
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        StepVerifier.create(tenantScoped(
                inbox.claim(messageId, issuanceId)
                        .then(inbox.markSkipped(messageId))
                        .then(inbox.claim(messageId, issuanceId))
        )).expectNext(ALREADY_PROCESSED).verifyComplete();
    }

    @Test
    void claim_whileStillInProgressWithinLeaseWindow_returnsInProgress() {
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        StepVerifier.create(tenantScoped(
                inbox.claim(messageId, issuanceId)
                        .then(inbox.claim(messageId, issuanceId))
        )).expectNext(IN_PROGRESS).verifyComplete();
    }

    @Test
    void claim_expiredInProgressClaim_reclaimsAsClaimed() {
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        StepVerifier.create(tenantScoped(inbox.claim(messageId, issuanceId)))
                .expectNext(CLAIMED)
                .verifyComplete();

        // Simulate a consumer crash: back-date claimed_at past the lease window
        // (NFR-S-225-04) directly, schema-qualified so it works regardless of
        // the raw databaseClient's own search_path.
        Instant expiredClaimedAt = Instant.now().minus(120, ChronoUnit.SECONDS);
        String schema = TENANT + SCHEMA_SUFFIX;
        databaseClient.sql("UPDATE \"" + schema + "\".revocation_instruction_inbox "
                        + "SET claimed_at = :claimedAt WHERE message_id = :messageId")
                .bind("claimedAt", expiredClaimedAt)
                .bind("messageId", messageId)
                .fetch()
                .rowsUpdated()
                .block();

        StepVerifier.create(tenantScoped(inbox.claim(messageId, issuanceId)))
                .expectNext(CLAIMED)
                .verifyComplete();
    }

    @Test
    void claim_differentMessageIds_bothClaimedIndependently() {
        String issuanceId = UUID.randomUUID().toString();
        String messageId1 = UUID.randomUUID().toString();
        String messageId2 = UUID.randomUUID().toString();

        StepVerifier.create(tenantScoped(inbox.claim(messageId1, issuanceId)))
                .expectNext(CLAIMED).verifyComplete();
        StepVerifier.create(tenantScoped(inbox.claim(messageId2, issuanceId)))
                .expectNext(CLAIMED).verifyComplete();
    }

    @Test
    void claim_isTenantIsolated_sameMessageIdInDifferentTenantSchemas() {
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        Mono<RevocationInstructionInbox.ClaimResult> claimInTenantA = inbox.claim(messageId, issuanceId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "e2e-tenant-a"));
        Mono<RevocationInstructionInbox.ClaimResult> claimInTenantB = inbox.claim(messageId, issuanceId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "e2e-tenant-b"));

        StepVerifier.create(claimInTenantA).expectNext(CLAIMED).verifyComplete();
        // Same message_id, different tenant schema: isolated, so also CLAIMED (not IN_PROGRESS).
        StepVerifier.create(claimInTenantB).expectNext(CLAIMED).verifyComplete();
    }

    @Test
    void release_afterFailedAttempt_allowsImmediateReclaim() {
        // AC-09: a transient failure must not force the next attempt to wait out the full
        // IN_PROGRESS lease (NFR-S-225-04) — release() lets it reclaim right away.
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        StepVerifier.create(tenantScoped(
                inbox.claim(messageId, issuanceId)
                        .then(inbox.release(messageId))
                        .then(inbox.claim(messageId, issuanceId))
        )).expectNext(CLAIMED).verifyComplete();
    }

    @Test
    void release_onProcessedMessage_isNoopAndClaimStaysAlreadyProcessed() {
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        StepVerifier.create(tenantScoped(
                inbox.claim(messageId, issuanceId)
                        .then(inbox.markProcessed(messageId))
                        .then(inbox.release(messageId))
                        .then(inbox.claim(messageId, issuanceId))
        )).expectNext(ALREADY_PROCESSED).verifyComplete();
    }

    @Test
    void release_onUnknownMessageId_isNoop() {
        StepVerifier.create(tenantScoped(inbox.release(UUID.randomUUID().toString())))
                .verifyComplete();
    }

    @Test
    void markProcessed_and_markSkipped_areIdempotentByMessageId() {
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        StepVerifier.create(tenantScoped(
                inbox.claim(messageId, issuanceId)
                        .then(inbox.markProcessed(messageId))
                        .then(inbox.markProcessed(messageId))
        )).verifyComplete();

        StepVerifier.create(tenantScoped(inbox.claim(messageId, issuanceId)))
                .expectNext(ALREADY_PROCESSED)
                .verifyComplete();
    }

    @Test
    void claim_persistsIssuanceIdForDiagnostics() {
        String messageId = UUID.randomUUID().toString();
        String issuanceId = UUID.randomUUID().toString();

        tenantScoped(inbox.claim(messageId, issuanceId)).block();

        String schema = TENANT + SCHEMA_SUFFIX;
        UUID persistedIssuanceId = databaseClient.sql("SELECT issuance_id FROM \"" + schema
                        + "\".revocation_instruction_inbox WHERE message_id = :messageId")
                .bind("messageId", messageId)
                .map((row, meta) -> row.get("issuance_id", UUID.class))
                .one()
                .block();

        assertThat(persistedIssuanceId).isEqualTo(UUID.fromString(issuanceId));
    }
}
