package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Result;
import es.in2.issuer.backend.signing.domain.spi.CallerIdentityPort;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.KeyState;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.RegisteredTenant;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.WithdrawnOwnKey;
import lombok.extern.slf4j.Slf4j;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Makes KMS reflect what the database says (EUD-289 B8): a withdrawn own-key configuration cannot be
 * withdrawn in KMS in the same step, so once it has been withdrawn for longer than the grace period its
 * key is disabled and scheduled for deletion. The grace period covers the Issuer instances that still hold
 * the previous configuration in cache.
 *
 * <p>Idempotent: a row whose key was retired is marked ({@code own_key_deleted_at}) and never selected
 * again, so a second run makes no KMS call. The key state is checked before acting, so an interrupted run
 * can be repeated. A key that an active configuration of any tenant references is never touched (a renewal keeps
 * the key of the configuration it replaces): the row is only marked. {@code DeleteImportedKeyMaterial} is not called: during the deletion window the key is
 * disabled but recoverable if the replacement was a mistake.
 *
 * <p>Every row leaves a {@code Retire} event: {@code Success} or {@code Denied} (key in use) staged in the
 * transaction that marks the row, {@code Failure} in a transaction of its own, since the row's transaction ends
 * without changes. The actor is the caller ARN. The correlation id is the operation id of the onboarding that activated
 * the row, the same as in its {@code Create} or {@code Replace} event, so the events of a key can be joined; it is
 * {@code null} for a row the onboarding tool did not write. The same transaction releases the SPKI reservation of the row of a key that
 * was retired: until then the public key is still reserved for its tenant. The reservation of a key that an active
 * configuration still references is not released, because the key still signs.
 *
 * <p>One transaction per row: the row is selected {@code FOR UPDATE SKIP LOCKED}, so two runs at the same
 * time never act on the same row, and a failure on one key leaves the others to proceed.
 */
@Slf4j
public class OwnKeyReconciler {

    private final KmsKeyAdministrationPort kms;
    private final OwnKeyStorePort store;
    private final CallerIdentityPort identity;
    private final Clock clock;
    private final int pendingDeletionDays;

    /** @param pendingDeletionDays waiting period of {@code ScheduleKeyDeletion} (KMS minimum is 7) */
    public OwnKeyReconciler(KmsKeyAdministrationPort kms, OwnKeyStorePort store, CallerIdentityPort identity,
                            Clock clock, int pendingDeletionDays) {
        this.kms = kms;
        this.store = store;
        this.identity = identity;
        this.clock = clock;
        this.pendingDeletionDays = pendingDeletionDays;
    }

    /**
     * @param retired  rows whose key is now retired and marked; on a dry run, the rows that would be processed
     * @param failures one line per tenant or key that could not be reconciled; the rest were processed
     */
    public record ReconcileReport(int retired, List<String> failures) {

        public boolean succeeded() {
            return failures.isEmpty();
        }
    }

    /** What happens to a row's key given its state. */
    private enum Action {
        DISABLE_AND_SCHEDULE,
        SCHEDULE,
        NONE,
        UNEXPECTED_STATE
    }

    /**
     * The caller ARN, asked of STS the first time a row is processed and not before: a run with nothing to retire
     * (the usual one, every 15 to 20 minutes) does not depend on STS.
     */
    private Supplier<String> actor() {
        return new Supplier<>() {
            private String arn;

            @Override
            public String get() {
                if (arn == null) {
                    arn = identity.callerArn();
                }
                return arn;
            }
        };
    }

    /** @param dryRun report what would be done: reads the database and the key states, writes nothing */
    public ReconcileReport reconcile(Duration grace, boolean dryRun) {
        int retired = 0;
        List<String> failures = new ArrayList<>();
        Supplier<String> actor = actor();
        for (String tenant : store.findActiveTenants()) {
            if (!store.findTenant(tenant).map(RegisteredTenant::schemaProvisioned).orElse(false)) {
                // Registered but not migrated yet (the Issuer creates the schema at startup): nothing to reconcile.
                log.warn("Tenant '{}' skipped: its Issuer schema is not provisioned", tenant);
                continue;
            }
            try {
                retired += dryRun ? planTenant(tenant, grace, failures) : reconcileTenant(tenant, grace, actor, failures);
            } catch (RuntimeException e) {
                log.error("Reconcile of tenant '{}' failed: {}", tenant, e.toString());
                failures.add("tenant " + tenant + ": " + e.getMessage());
            }
        }
        return new ReconcileReport(retired, failures);
    }

    private int reconcileTenant(String tenant, Duration grace, Supplier<String> actor, List<String> failures) {
        Set<UUID> failed = new HashSet<>();
        int retired = 0;
        while (true) {
            Optional<RowResult> result = store.inTransaction(tx -> tx.lockNextWithdrawnOwnKey(tenant, grace, failed)
                    .map(row -> retire(tx, tenant, row, actor)));
            if (result.isEmpty()) {
                return retired;
            }
            if (result.get().failure() == null) {
                retired++;
            } else {
                failed.add(result.get().row().id());
                failures.add(result.get().failure());
                recordFailure(tenant, result.get().row(), actor);
            }
        }
    }

    /** A failure is returned, not thrown, so the transaction ends and the row stays as it was. */
    private RowResult retire(OwnKeyStorePort.ConfigurationTransaction tx, String tenant, WithdrawnOwnKey row,
                             Supplier<String> actorOf) {
        Instant startedAt = clock.instant();
        try {
            // Before KMS is touched: a row is not retired without knowing who did it.
            String actor = actorOf.get();
            if (store.isKeyReferenced(row.kmsKeyRef(), true)) {
                log.warn("Tenant '{}', configuration {}: the key is referenced by an active configuration and is not "
                        + "retired", tenant, row.id());
                // The key still signs: its row is handled, but its SPKI stays reserved for the tenant.
                tx.markKeyStillInUse(tenant, row);
                tx.stage(event(tenant, row, Result.DENIED, RejectionReason.KEY_IN_USE, actor, startedAt));
                return new RowResult(row, null);
            }
            KeyState state = kms.describeKeyState(row.kmsKeyRef());
            switch (actionFor(state)) {
                case DISABLE_AND_SCHEDULE -> {
                    kms.disableKey(row.kmsKeyRef());
                    kms.scheduleKeyDeletion(row.kmsKeyRef(), pendingDeletionDays);
                }
                case SCHEDULE -> kms.scheduleKeyDeletion(row.kmsKeyRef(), pendingDeletionDays);
                case NONE -> log.info("Tenant '{}', configuration {}: the key is already {}", tenant, row.id(), state);
                case UNEXPECTED_STATE -> throw new OnboardingFailedException("the key is in an unexpected state");
            }
            tx.markKeyRetired(tenant, row);
            tx.stage(event(tenant, row, Result.SUCCESS, null, actor, startedAt));
            log.info("Tenant '{}', configuration {}: key retired (was {})", tenant, row.id(), state);
            return new RowResult(row, null);
        } catch (RuntimeException e) {
            log.error("Tenant '{}', configuration {}: the key could not be retired: {}", tenant, row.id(), e.toString());
            return new RowResult(row, rowFailure(tenant, row, e));
        }
    }

    private SigningConfigurationChanged event(String tenant, WithdrawnOwnKey row, Result result, RejectionReason reason,
                                              String actor, Instant startedAt) {
        Instant now = clock.instant();
        return SigningConfigurationChanged.retire(tenant, result, reason, actor, Duration.between(startedAt, now), now,
                row.operationId());
    }

    /** The row's transaction made no change, so the failure goes in a transaction of its own. */
    private void recordFailure(String tenant, WithdrawnOwnKey row, Supplier<String> actor) {
        try {
            store.recordInOwnTransaction(SigningConfigurationChanged.retire(tenant, Result.FAILURE,
                    RejectionReason.PROVIDER_UNAVAILABLE, actor.get(), Duration.ZERO, clock.instant(), row.operationId()));
        } catch (RuntimeException e) {
            log.error("Tenant '{}', configuration {}: the failed retirement could not be recorded: {}", tenant,
                    row.id(), e.toString());
        }
    }

    private int planTenant(String tenant, Duration grace, List<String> failures) {
        List<WithdrawnOwnKey> pending = store.findWithdrawnOwnKeysPendingKms(tenant, grace);
        for (WithdrawnOwnKey row : pending) {
            try {
                if (store.isKeyReferenced(row.kmsKeyRef(), true)) {
                    log.info("Dry run. Tenant '{}', configuration {}: the key is referenced by an active configuration, "
                            + "would only mark the row", tenant, row.id());
                    continue;
                }
                KeyState state = kms.describeKeyState(row.kmsKeyRef());
                log.info("Dry run. Tenant '{}', configuration {}: key is {}, would {}", tenant, row.id(), state,
                        actionFor(state));
            } catch (RuntimeException e) {
                failures.add(rowFailure(tenant, row, e));
            }
        }
        return pending.size();
    }

    private static String rowFailure(String tenant, WithdrawnOwnKey row, RuntimeException e) {
        return "tenant " + tenant + ", configuration " + row.id() + ": " + e.getMessage();
    }

    private static Action actionFor(KeyState state) {
        return switch (state) {
            case ENABLED -> Action.DISABLE_AND_SCHEDULE;
            case DISABLED -> Action.SCHEDULE;
            case PENDING_DELETION, NOT_FOUND -> Action.NONE;
            case PENDING_IMPORT, OTHER -> Action.UNEXPECTED_STATE;
        };
    }

    private record RowResult(WithdrawnOwnKey row, String failure) {}
}
