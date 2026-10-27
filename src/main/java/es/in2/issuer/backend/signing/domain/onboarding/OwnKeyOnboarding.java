package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.spi.CallerIdentityPort;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.ImportParameters;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.KeyState;
import es.in2.issuer.backend.signing.domain.spi.OnboardingArtifactsPort;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.ActiveConfiguration;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.ConfigurationTransaction;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.NewOwnKeyConfiguration;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.RegisteredTenant;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.SpkiReservation;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.WithdrawnOwnKey;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Operation;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Result;
import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Onboarding of a tenant's own key in KMS (EUD-289 B8), in two executions because the customer wraps its
 * private key with a public key that only KMS can give once the key exists:
 *
 * <ol>
 *   <li>{@link #prepare}: validates, creates the key (origin external, tagged for the tenant) and hands out
 *       the wrapping public key and the import token.</li>
 *   <li>{@link #importKey}: validates again (the state may be stale), imports the wrapped key material,
 *       checks that the key's public key is the certificate's and, in one database transaction, withdraws
 *       the previous active configuration, activates the new one, reserves the SPKI and stages the audit
 *       event.</li>
 * </ol>
 *
 * <p>A certificate renewal that keeps the key is a third case: when the SPKI is reserved by the tenant's own
 * active own-key configuration, the key material is already in that configuration's KMS key, so nothing is
 * created or imported. {@code prepare} checks the key and leaves a state marked as a renewal, and
 * {@code import} (without key material) checks again that the existing key is the certificate's and swaps the
 * rows in one transaction, with the same KMS key. That key is never disabled or scheduled for deletion, not even
 * when the renewal fails. {@link #discard} gives up a preparation that was never imported.
 *
 * <p>The tool never receives a private key in clear and never signs: the role that runs it has no
 * {@code kms:Sign}. A KMS key that an onboarding created and could not complete is disabled and scheduled
 * for deletion, so none is left orphaned.
 */
@Slf4j
public class OwnKeyOnboarding {

    /** Same shape as the tenant schema names the Issuer accepts. */
    private static final Pattern TENANT_ID = Pattern.compile("^[a-z][a-z0-9_-]{0,62}$");

    private final KmsKeyAdministrationPort kms;
    private final OwnKeyStorePort store;
    private final CallerIdentityPort identity;
    private final Clock clock;
    private final Supplier<String> operationIds;
    private final int pendingDeletionDays;

    /**
     * @param operationIds        generates the id of each onboarding
     * @param pendingDeletionDays waiting period of {@code ScheduleKeyDeletion} for a key that is cleaned up
     */
    public OwnKeyOnboarding(KmsKeyAdministrationPort kms, OwnKeyStorePort store, CallerIdentityPort identity,
                            Clock clock, Supplier<String> operationIds, int pendingDeletionDays) {
        this.kms = kms;
        this.store = store;
        this.identity = identity;
        this.clock = clock;
        this.operationIds = operationIds;
        this.pendingDeletionDays = pendingDeletionDays;
    }

    /**
     * @param tenant   tenant id
     * @param chainPem the certificate chain, PEM, leaf first and root excluded
     * @param alias    full alias name ({@code alias/...}); {@code null} derives one from the tenant and the operation id
     * @param dryRun   run the validations only: nothing is written to KMS, files or the database
     * @param artifacts where the wrapping public key, the import token and the state are left; unused on a dry run
     */
    public record PrepareCommand(String tenant, String chainPem, OnboardingPolicy policy, String alias, boolean dryRun,
                                 OnboardingArtifactsPort artifacts) {}

    /** @param prepared the state left for {@code import}; {@code null} on a dry run */
    public record PrepareResult(PreparedOnboarding prepared, Operation operation, String spkiSha256) {}

    /**
     * @param prepared             the state {@code prepare} left
     * @param importToken          the token {@code prepare} left
     * @param encryptedKeyMaterial the private key, wrapped by the customer with the wrapping public key
     * @param dryRun               run the validations only: nothing is written to KMS or the database
     */
    public record ImportCommand(PreparedOnboarding prepared, byte[] importToken, byte[] encryptedKeyMaterial,
                                OnboardingPolicy policy, boolean dryRun) {}

    /** @param configurationId id of the new active row; {@code null} on a dry run */
    public record ImportResult(String keyArn, UUID configurationId, Operation operation, String spkiSha256) {}

    /**
     * @param prepared  the state {@code prepare} left
     * @param dryRun    only check that the preparation can be discarded
     * @param artifacts where the state is marked as discarded
     */
    public record DiscardCommand(PreparedOnboarding prepared, boolean dryRun, OnboardingArtifactsPort artifacts) {}

    public enum DiscardOutcome {
        /** The key was disabled and scheduled for deletion, its alias deleted and the state marked. */
        DISCARDED,
        /** Nothing to do: it was discarded before, or the key is already pending deletion or gone. */
        ALREADY_DISCARDED,
        /** A dry run: the preparation can be discarded. */
        WOULD_DISCARD
    }

    public record DiscardResult(String keyArn, DiscardOutcome outcome) {}

    /** What an onboarding attempt knows about itself, for the event of a rejection. */
    private static final class Attempt {
        private final String tenant;
        private final String actor;
        private final Instant startedAt;
        private SigningModality previousModality;
        private String certificateSha256;
        private String operationId;
        /** Set when the certificate renews the key of the tenant's active configuration. */
        private String renewalKeyArn;

        private Attempt(String tenant, String actor, Instant startedAt) {
            this.tenant = tenant;
            this.actor = actor;
            this.startedAt = startedAt;
        }

        private Operation operation() {
            return previousModality == null ? Operation.CREATE : Operation.REPLACE;
        }
    }

    public PrepareResult prepare(PrepareCommand command) {
        requireTenantId(command.tenant());
        Attempt attempt = new Attempt(command.tenant(), command.dryRun() ? null : identity.callerArn(), clock.instant());
        ValidatedOwnKeyCertificate certificate = validatedOrRejected(attempt,
                () -> OwnKeyCertificateValidator.parsePemChain(command.chainPem()), command.policy(), command.dryRun());
        if (attempt.renewalKeyArn != null) {
            try {
                requireExistingKeyIsTheCertificates(attempt, certificate);
            } catch (OnboardingRejectedException rejected) {
                if (!command.dryRun()) {
                    recordRejection(attempt, rejected);
                }
                throw rejected;
            }
        }
        if (command.dryRun()) {
            return new PrepareResult(null, attempt.operation(), certificate.spkiSha256Hex());
        }
        attempt.operationId = operationIds.get();
        if (attempt.renewalKeyArn != null) {
            PreparedOnboarding renewal = new PreparedOnboarding(attempt.operationId, command.tenant(),
                    attempt.renewalKeyArn, null, certificate.chainBase64(), certificate.spkiSha256Hex(),
                    clock.instant(), null, true, null);
            command.artifacts().write(renewal, null, null);
            return new PrepareResult(renewal, attempt.operation(), certificate.spkiSha256Hex());
        }
        String alias = command.alias() != null ? command.alias() : defaultAlias(command.tenant(), attempt.operationId);
        String keyArn = kms.createKey(command.tenant(), attempt.operationId);
        try {
            kms.createAlias(alias, keyArn);
            ImportParameters parameters = kms.getParametersForImport(keyArn);
            PreparedOnboarding prepared = new PreparedOnboarding(attempt.operationId, command.tenant(), keyArn, alias,
                    certificate.chainBase64(), certificate.spkiSha256Hex(), clock.instant(), parameters.validTo());
            command.artifacts().write(prepared, parameters.wrappingPublicKeyDer(), parameters.importToken());
            return new PrepareResult(prepared, attempt.operation(), certificate.spkiSha256Hex());
        } catch (RuntimeException e) {
            discardKey(keyArn, e);
            throw e;
        }
    }

    public ImportResult importKey(ImportCommand command) {
        PreparedOnboarding prepared = command.prepared();
        requireTenantId(prepared.tenant());
        Attempt attempt = new Attempt(prepared.tenant(), command.dryRun() ? null : identity.callerArn(), clock.instant());
        attempt.operationId = prepared.operationId();

        if (prepared.discardedAt() != null) {
            throw new OnboardingFailedException("this preparation was discarded at " + prepared.discardedAt()
                    + ": run prepare again");
        }
        ValidatedOwnKeyCertificate certificate;
        try {
            certificate = validatedOrRejected(attempt,
                    () -> OwnKeyCertificateValidator.parseBase64Chain(prepared.certificateChain()),
                    command.policy(), command.dryRun());
            requireStateOfItsChain(prepared, certificate);
            requireSameKindOfOnboarding(prepared, attempt);
        } catch (OnboardingRejectedException rejected) {
            // A renewal created nothing: the key it names is the active one and is never discarded.
            if (!command.dryRun() && !prepared.renewal()) {
                discardKey(prepared.keyArn(), rejected);
            }
            throw rejected;
        }
        if (prepared.renewal()) {
            if (command.dryRun()) {
                return new ImportResult(prepared.keyArn(), null, attempt.operation(), certificate.spkiSha256Hex());
            }
            return renewAndActivate(command, attempt, certificate);
        }
        if (!clock.instant().isBefore(prepared.importTokenExpiresAt())) {
            OnboardingFailedException expired = new OnboardingFailedException("the import token expired at "
                    + prepared.importTokenExpiresAt() + ": run prepare again");
            if (!command.dryRun()) {
                discardKey(prepared.keyArn(), expired);
            }
            throw expired;
        }
        if (command.dryRun()) {
            return new ImportResult(prepared.keyArn(), null, attempt.operation(), certificate.spkiSha256Hex());
        }
        return importAndActivate(command, attempt, certificate);
    }

    /** What {@code prepare} decided (new key or renewal) must still be true: the tenant may have changed since. */
    private static void requireSameKindOfOnboarding(PreparedOnboarding prepared, Attempt attempt) {
        boolean renewalNow = attempt.renewalKeyArn != null;
        if (prepared.renewal() != renewalNow || (renewalNow && !attempt.renewalKeyArn.equals(prepared.keyArn()))) {
            throw new OnboardingRejectedException(RejectionReason.POLICY_DENIED,
                    "the active configuration of the tenant changed since prepare: run prepare again");
        }
    }

    /**
     * Renewal: no key is created or imported. The existing key must be the certificate's, and a failure here
     * never touches it: it is the key the tenant signs with.
     */
    private ImportResult renewAndActivate(ImportCommand command, Attempt attempt, ValidatedOwnKeyCertificate certificate) {
        PreparedOnboarding prepared = command.prepared();
        try {
            requireExistingKeyIsTheCertificates(attempt, certificate);
            UUID configurationId = store.inTransaction(tx -> activate(tx, attempt, prepared, certificate));
            return new ImportResult(prepared.keyArn(), configurationId, attempt.operation(), certificate.spkiSha256Hex());
        } catch (OnboardingRejectedException rejected) {
            recordRejection(attempt, rejected);
            throw rejected;
        }
    }

    private void requireExistingKeyIsTheCertificates(Attempt attempt, ValidatedOwnKeyCertificate certificate) {
        if (!MessageDigest.isEqual(kms.getPublicKey(attempt.renewalKeyArn), certificate.spkiDer())) {
            throw new OnboardingRejectedException(RejectionReason.INVALID_KEY,
                    "the public key of the existing KMS key is not the public key of the new certificate");
        }
    }

    /**
     * Gives up a preparation that was never imported: its KMS key is disabled if possible, scheduled for
     * deletion and its alias deleted, and the state is marked. It refuses (rejection) a key that is not the one
     * of this preparation (the tags {@code operationId} and {@code Tenant} must match the state), a key that has
     * key material, and a key that any signing configuration of any tenant references.
     */
    public DiscardResult discard(DiscardCommand command) {
        PreparedOnboarding prepared = command.prepared();
        requireTenantId(prepared.tenant());
        if (prepared.renewal()) {
            throw new OnboardingFailedException("a renewal created no KMS key: there is nothing to discard");
        }
        if (prepared.discardedAt() != null) {
            return new DiscardResult(prepared.keyArn(), DiscardOutcome.ALREADY_DISCARDED);
        }
        KeyState state = kms.describeKeyState(prepared.keyArn());
        if (state == KeyState.NOT_FOUND || state == KeyState.PENDING_DELETION) {
            if (!command.dryRun()) {
                command.artifacts().markDiscarded(prepared, clock.instant());
            }
            return new DiscardResult(prepared.keyArn(), DiscardOutcome.ALREADY_DISCARDED);
        }
        if (state != KeyState.PENDING_IMPORT) {
            throw new OnboardingRejectedException(RejectionReason.POLICY_DENIED, "the key is " + state
                    + ", not waiting for its key material: it has been imported and is not discarded");
        }
        requireKeyOfThisPreparation(prepared);
        if (store.isKeyReferenced(prepared.keyArn(), false)) {
            throw new OnboardingRejectedException(RejectionReason.POLICY_DENIED,
                    "a signing configuration references the key: it is not discarded");
        }
        if (command.dryRun()) {
            return new DiscardResult(prepared.keyArn(), DiscardOutcome.WOULD_DISCARD);
        }
        try {
            kms.disableKey(prepared.keyArn());
        } catch (RuntimeException e) {
            log.debug("DisableKey of {} was not applied (a key waiting for its material cannot be disabled): {}",
                    prepared.keyArn(), e.toString());
        }
        kms.scheduleKeyDeletion(prepared.keyArn(), pendingDeletionDays);
        try {
            kms.deleteAlias(prepared.alias());
        } catch (RuntimeException e) {
            log.warn("The key {} is scheduled for deletion but its alias {} could not be deleted: {}",
                    prepared.keyArn(), prepared.alias(), e.toString());
        }
        command.artifacts().markDiscarded(prepared, clock.instant());
        return new DiscardResult(prepared.keyArn(), DiscardOutcome.DISCARDED);
    }

    private void requireKeyOfThisPreparation(PreparedOnboarding prepared) {
        Map<String, String> tags = kms.listTags(prepared.keyArn());
        if (!prepared.operationId().equals(tags.get("operationId")) || !prepared.tenant().equals(tags.get("Tenant"))) {
            throw new OnboardingRejectedException(RejectionReason.POLICY_DENIED,
                    "the tags of the key are not those of this preparation (operationId, Tenant): it is not discarded");
        }
    }

    /**
     * From the {@code ImportKeyMaterial} call on, any failure disables and schedules the deletion of the key.
     * Nothing after the commit of the transaction may throw: it would discard a key that is already active.
     */
    private ImportResult importAndActivate(ImportCommand command, Attempt attempt, ValidatedOwnKeyCertificate certificate) {
        PreparedOnboarding prepared = command.prepared();
        try {
            kms.importKeyMaterial(prepared.keyArn(), command.importToken(), command.encryptedKeyMaterial());
            if (!MessageDigest.isEqual(kms.getPublicKey(prepared.keyArn()), certificate.spkiDer())) {
                throw new OnboardingRejectedException(RejectionReason.INVALID_KEY,
                        "the public key of the imported KMS key is not the public key of the certificate");
            }
            UUID configurationId = store.inTransaction(tx -> activate(tx, attempt, prepared, certificate));
            return new ImportResult(prepared.keyArn(), configurationId, attempt.operation(), certificate.spkiSha256Hex());
        } catch (OnboardingRejectedException rejected) {
            discardKey(prepared.keyArn(), rejected);
            recordRejection(attempt, rejected);
            throw rejected;
        } catch (CommitOutcomeUnknownException unknown) {
            log.error("The outcome of the commit is unknown: the KMS key {} may be the active one and was NOT "
                    + "disabled. Check tenant_signing_config before doing anything else.", prepared.keyArn());
            throw unknown;
        } catch (RuntimeException failure) {
            discardKey(prepared.keyArn(), failure);
            throw failure;
        }
    }

    private UUID activate(ConfigurationTransaction tx, Attempt attempt, PreparedOnboarding prepared,
                          ValidatedOwnKeyCertificate certificate) {
        var previous = tx.lockActiveConfiguration(attempt.tenant);
        if (prepared.renewal()) {
            // Under the lock: the active row must still be the one that holds this key.
            ActiveConfiguration active = previous.filter(row -> row.modality() == SigningModality.OWN_KEY
                            && prepared.keyArn().equals(row.kmsKeyRef()))
                    .orElseThrow(() -> new OnboardingRejectedException(RejectionReason.POLICY_DENIED,
                            "the active configuration of the tenant changed since prepare: run prepare again"));
            tx.withdraw(attempt.tenant, active, attempt.actor);
            // The key is still the active one: mark the row handled so that reconcile does not retire it.
            tx.markKeyRetired(attempt.tenant, new WithdrawnOwnKey(active.id(), attempt.tenant, active.kmsKeyRef()));
        } else {
            previous.ifPresent(active -> tx.withdraw(attempt.tenant, active, attempt.actor));
        }
        UUID configurationId = tx.activateOwnKey(attempt.tenant,
                new NewOwnKeyConfiguration(prepared.keyArn(), certificate.chainBase64()), attempt.actor);
        tx.reserveSpki(certificate.spkiSha256(), attempt.tenant, configurationId);
        tx.stage(event(attempt, previous.isPresent() ? Operation.REPLACE : Operation.CREATE,
                previous.map(ActiveConfiguration::modality).orElse(null), Result.SUCCESS, null,
                certificate.certificateSha256Hex()));
        return configurationId;
    }

    /**
     * The checks before anything is created or imported: the certificate, then the tenant, then the SPKI.
     * A rejection is recorded in a transaction of its own, except on a dry run, which writes nothing.
     */
    private ValidatedOwnKeyCertificate validatedOrRejected(Attempt attempt, Supplier<List<X509Certificate>> chain,
                                                           OnboardingPolicy policy, boolean dryRun) {
        try {
            return validate(attempt, chain.get(), policy);
        } catch (OnboardingRejectedException rejected) {
            if (!dryRun) {
                recordRejection(attempt, rejected);
            }
            throw rejected;
        }
    }

    private ValidatedOwnKeyCertificate validate(Attempt attempt, List<X509Certificate> chain, OnboardingPolicy policy) {
        attempt.certificateSha256 = new ValidatedOwnKeyCertificate(chain).certificateSha256Hex();
        ValidatedOwnKeyCertificate certificate = OwnKeyCertificateValidator.validate(chain, policy, clock.instant());
        RegisteredTenant tenant = store.findTenant(attempt.tenant).orElseThrow(() -> unavailableTenant(
                attempt, "tenant '" + attempt.tenant + "' is not in the tenant registry"));
        if (!tenant.active()) {
            throw unavailableTenant(attempt, "tenant '" + attempt.tenant + "' is not active in the tenant registry");
        }
        if (!tenant.schemaProvisioned()) {
            throw new OnboardingRejectedException(RejectionReason.POLICY_DENIED,
                    "the Issuer schema of tenant '" + attempt.tenant + "' does not exist or has no signing configuration table");
        }
        attempt.previousModality = tenant.activeModality();
        store.findSpkiReservation(certificate.spkiSha256()).ifPresent(reservation -> {
            if (!isRenewalOfTheActiveKey(reservation, tenant)) {
                throw new OnboardingRejectedException(RejectionReason.KEY_IN_USE, "the key (SPKI sha256 "
                        + certificate.spkiSha256Hex() + ") is already reserved by tenant '" + reservation.tenantId() + "'");
            }
            attempt.renewalKeyArn = tenant.activeKmsKeyRef();
        });
        return certificate;
    }

    /**
     * A reservation is a renewal, not a conflict, only when it belongs to this tenant and to the very row that is
     * its active own-key configuration. A stale reservation of the same tenant, or any other holder, is a conflict.
     */
    private static boolean isRenewalOfTheActiveKey(SpkiReservation reservation, RegisteredTenant tenant) {
        return tenant.activeModality() == SigningModality.OWN_KEY
                && tenant.activeKmsKeyRef() != null
                && tenant.id().equals(reservation.tenantId())
                && reservation.configurationId().equals(tenant.activeConfigurationId());
    }

    /** The state file says which key the chain belongs to: a state that does not agree with its own chain is not trusted. */
    private static void requireStateOfItsChain(PreparedOnboarding prepared, ValidatedOwnKeyCertificate certificate) {
        if (!certificate.spkiSha256Hex().equalsIgnoreCase(prepared.spkiSha256())) {
            throw new OnboardingFailedException("the state file does not match its own certificate chain");
        }
    }

    /**
     * Audited like any other rejection, with the tenant id as given: the audit API keeps the events of a tenant it
     * does not know as rejected events of its own. The line tells the operator which tenant was not found.
     */
    private static OnboardingRejectedException unavailableTenant(Attempt attempt, String message) {
        log.warn("Onboarding of tenant '{}' rejected: {}", attempt.tenant, message);
        return new OnboardingRejectedException(RejectionReason.POLICY_DENIED, message);
    }

    private void recordRejection(Attempt attempt, OnboardingRejectedException rejected) {
        try {
            store.recordInOwnTransaction(event(attempt, attempt.operation(), attempt.previousModality, Result.DENIED,
                    rejected.getReason(), attempt.certificateSha256));
        } catch (RuntimeException e) {
            log.error("The rejected onboarding of tenant '{}' could not be recorded: {}", attempt.tenant, e.toString());
            rejected.addSuppressed(e);
        }
    }

    private SigningConfigurationChanged event(Attempt attempt, Operation operation, SigningModality previousModality,
                                              Result result, RejectionReason reason, String certificateSha256) {
        Instant now = clock.instant();
        return new SigningConfigurationChanged(attempt.tenant, operation, result, reason, previousModality,
                SigningModality.OWN_KEY, certificateSha256, attempt.actor, Duration.between(attempt.startedAt, now), now,
                attempt.operationId);
    }

    /**
     * Compensation: the key that an onboarding created and did not complete is disabled and scheduled for
     * deletion. A key that has no material yet cannot be disabled, so that step is allowed to fail; if the
     * deletion cannot be scheduled the operator is told which key to retire by hand.
     */
    private void discardKey(String keyArn, Throwable cause) {
        try {
            kms.disableKey(keyArn);
        } catch (RuntimeException e) {
            log.debug("DisableKey of {} was not applied (a key waiting for its material cannot be disabled): {}",
                    keyArn, e.toString());
        }
        try {
            kms.scheduleKeyDeletion(keyArn, pendingDeletionDays);
            log.warn("The KMS key {} was not put into service: it is disabled and scheduled for deletion", keyArn);
        } catch (RuntimeException e) {
            log.error("The KMS key {} was not put into service and its deletion could not be scheduled: "
                    + "disable it and schedule its deletion by hand", keyArn);
            cause.addSuppressed(e);
        }
    }

    private static String defaultAlias(String tenant, String operationId) {
        return "alias/own-key-" + tenant + "-" + operationId;
    }

    private static void requireTenantId(String tenant) {
        if (tenant == null || !TENANT_ID.matcher(tenant).matches()) {
            throw new IllegalArgumentException("the tenant id must be lowercase letters, digits, '-' or '_', "
                    + "start with a letter and have at most 63 characters");
        }
    }
}
