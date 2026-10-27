package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.KeyState;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.RegisteredTenant;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.WithdrawnOwnKey;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Makes KMS reflect what the database says (EUD-289 B8): a withdrawn own-key configuration cannot be
 * withdrawn in KMS in the same step, so once it has been withdrawn for longer than the grace period its
 * key is disabled and scheduled for deletion. The grace period covers the Issuer instances that still hold
 * the previous configuration in cache.
 *
 * <p>Idempotent: a row whose key was retired is marked ({@code own_key_deleted_at}) and never selected
 * again, so a second run makes no KMS call. The key state is checked before acting, so an interrupted run
 * can be repeated. {@code DeleteImportedKeyMaterial} is not called: during the deletion window the key is
 * disabled but recoverable if the replacement was a mistake.
 *
 * <p>One transaction per row: the row is selected {@code FOR UPDATE SKIP LOCKED}, so two runs at the same
 * time never act on the same row, and a failure on one key leaves the others to proceed.
 */
@Slf4j
public class OwnKeyReconciler {

    private final KmsKeyAdministrationPort kms;
    private final OwnKeyStorePort store;
    private final int pendingDeletionDays;

    /** @param pendingDeletionDays waiting period of {@code ScheduleKeyDeletion} (KMS minimum is 7) */
    public OwnKeyReconciler(KmsKeyAdministrationPort kms, OwnKeyStorePort store, int pendingDeletionDays) {
        this.kms = kms;
        this.store = store;
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

    /** @param dryRun report what would be done: reads the database and the key states, writes nothing */
    public ReconcileReport reconcile(Duration grace, boolean dryRun) {
        int retired = 0;
        List<String> failures = new ArrayList<>();
        for (String tenant : store.findActiveTenants()) {
            if (!store.findTenant(tenant).map(RegisteredTenant::schemaProvisioned).orElse(false)) {
                // Registered but not migrated yet (the Issuer creates the schema at startup): nothing to reconcile.
                log.warn("Tenant '{}' skipped: its Issuer schema is not provisioned", tenant);
                continue;
            }
            try {
                retired += dryRun ? planTenant(tenant, grace, failures) : reconcileTenant(tenant, grace, failures);
            } catch (RuntimeException e) {
                log.error("Reconcile of tenant '{}' failed: {}", tenant, e.toString());
                failures.add("tenant " + tenant + ": " + e.getMessage());
            }
        }
        return new ReconcileReport(retired, failures);
    }

    private int reconcileTenant(String tenant, Duration grace, List<String> failures) {
        Set<UUID> failed = new HashSet<>();
        int retired = 0;
        while (true) {
            Optional<RowResult> result = store.inTransaction(tx -> tx.lockNextWithdrawnOwnKey(tenant, grace, failed)
                    .map(row -> retire(tx, tenant, row)));
            if (result.isEmpty()) {
                return retired;
            }
            if (result.get().failure() == null) {
                retired++;
            } else {
                failed.add(result.get().id());
                failures.add(result.get().failure());
            }
        }
    }

    /** A failure is returned, not thrown, so the transaction ends and the row stays as it was. */
    private RowResult retire(OwnKeyStorePort.ConfigurationTransaction tx, String tenant, WithdrawnOwnKey row) {
        try {
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
            log.info("Tenant '{}', configuration {}: key retired (was {})", tenant, row.id(), state);
            return new RowResult(row.id(), null);
        } catch (RuntimeException e) {
            log.error("Tenant '{}', configuration {}: the key could not be retired: {}", tenant, row.id(), e.toString());
            return new RowResult(row.id(), "tenant " + tenant + ", configuration " + row.id() + ": " + e.getMessage());
        }
    }

    private int planTenant(String tenant, Duration grace, List<String> failures) {
        List<WithdrawnOwnKey> pending = store.findWithdrawnOwnKeysPendingKms(tenant, grace);
        for (WithdrawnOwnKey row : pending) {
            try {
                KeyState state = kms.describeKeyState(row.kmsKeyRef());
                log.info("Dry run. Tenant '{}', configuration {}: key is {}, would {}", tenant, row.id(), state,
                        actionFor(state));
            } catch (RuntimeException e) {
                failures.add("tenant " + tenant + ", configuration " + row.id() + ": " + e.getMessage());
            }
        }
        return pending.size();
    }

    private static Action actionFor(KeyState state) {
        return switch (state) {
            case ENABLED -> Action.DISABLE_AND_SCHEDULE;
            case DISABLED -> Action.SCHEDULE;
            case PENDING_DELETION, NOT_FOUND -> Action.NONE;
            case OTHER -> Action.UNEXPECTED_STATE;
        };
    }

    private record RowResult(UUID id, String failure) {}
}
