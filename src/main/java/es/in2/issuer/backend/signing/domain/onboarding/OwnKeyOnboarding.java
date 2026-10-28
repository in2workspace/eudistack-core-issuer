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
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.OperationLock;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.RegisteredTenant;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.SpkiReservation;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.WithdrawnOwnKey;
import es.in2.issuer.backend.signing.domain.util.KeyRefs;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Operation;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Result;
import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
    private static final String RESERVED_TENANT = "unknown";

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
     * @param artifacts            where the state is marked as consumed after a successful import; may be null
     */
    public record ImportCommand(PreparedOnboarding prepared, byte[] importToken, byte[] encryptedKeyMaterial,
                                OnboardingPolicy policy, boolean dryRun, OnboardingArtifactsPort artifacts) {

        public ImportCommand(PreparedOnboarding prepared, byte[] importToken, byte[] encryptedKeyMaterial,
                             OnboardingPolicy policy, boolean dryRun) {
            this(prepared, importToken, encryptedKeyMaterial, policy, dryRun, null);
        }
    }

    /** The KMS key a preparation created, as far as the checks and the cleanup need to know it. */
    private record OwnKey(String arn, String tenant, String operationId, String alias) {

        static OwnKey of(PreparedOnboarding prepared) {
            return new OwnKey(prepared.keyArn(), prepared.tenant(), prepared.operationId(), prepared.alias());
        }
    }

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
        /** Set once the {@code ImportKeyMaterial} of THIS run succeeded: only then may the key be found enabled. */
        private boolean keyMaterialImported;

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
                    clock.instant(), null, true, null, null, command.policy().summary());
            command.artifacts().write(renewal, null, null);
            return new PrepareResult(renewal, attempt.operation(), certificate.spkiSha256Hex());
        }
        String alias = command.alias() != null ? command.alias() : defaultAlias(command.tenant(), attempt.operationId);
        String keyArn = kms.createKey(command.tenant(), attempt.operationId);
        try {
            kms.createAlias(alias, keyArn);
            ImportParameters parameters = kms.getParametersForImport(keyArn);
            PreparedOnboarding prepared = new PreparedOnboarding(attempt.operationId, command.tenant(), keyArn, alias,
                    certificate.chainBase64(), certificate.spkiSha256Hex(), clock.instant(), parameters.validTo(), false, null,
                    null, command.policy().summary());
            command.artifacts().write(prepared, parameters.wrappingPublicKeyDer(), parameters.importToken());
            return new PrepareResult(prepared, attempt.operation(), certificate.spkiSha256Hex());
        } catch (RuntimeException e) {
            retireOwnNewKey(new OwnKey(keyArn, command.tenant(), attempt.operationId, alias), PENDING_ONLY, e);
            throw e;
        }
    }

    /**
     * A real run holds the lock of its operation from before the first check until it has ended, so two runs of the
     * same state cannot overlap: without it, one could find the key the other has just imported enabled and take it
     * for its own to clean up. A run that cannot take the lock ends with an error before any call to KMS.
     */
    public ImportResult importKey(ImportCommand command) {
        PreparedOnboarding prepared = command.prepared();
        requireTenantId(prepared.tenant());
        // A consumed or discarded state is refused before anything else, with no call to KMS: repeating an import
        // must not be able to touch a key.
        if (prepared.importedAt() != null) {
            throw new OnboardingFailedException("this preparation was already imported at " + prepared.importedAt()
                    + ": it cannot be used again");
        }
        if (prepared.discardedAt() != null) {
            throw new OnboardingFailedException("this preparation was discarded at " + prepared.discardedAt()
                    + ": run prepare again");
        }
        if (command.dryRun()) {
            return runImport(command);
        }
        try (OperationLock ignored = store.tryLockOperation(prepared.operationId()).orElseThrow(
                () -> new OnboardingFailedException("another run is importing this preparation (operation "
                        + prepared.operationId() + "): nothing was touched in KMS. Wait for it to end and check its "
                        + "result before trying again"))) {
            return runImport(command);
        }
    }

    private ImportResult runImport(ImportCommand command) {
        PreparedOnboarding prepared = command.prepared();
        Attempt attempt = new Attempt(prepared.tenant(), command.dryRun() ? null : identity.callerArn(), clock.instant());
        attempt.operationId = prepared.operationId();
        OwnKey key = OwnKey.of(prepared);

        if (!prepared.renewal()) {
            requireTheKeyOfThisPreparation(key, attempt, command.dryRun());
        }
        requireNoLaxerPolicyThanPrepare(prepared, command, attempt);
        ValidatedOwnKeyCertificate certificate;
        try {
            certificate = validatedOrRejected(attempt,
                    () -> OwnKeyCertificateValidator.parseBase64Chain(prepared.certificateChain()),
                    command.policy(), command.dryRun());
        } catch (OnboardingRejectedException rejected) {
            retireIfNewKey(prepared, key, command.dryRun(), PENDING_ONLY, rejected);
            throw rejected;
        }
        try {
            requireStateOfItsChain(prepared, certificate);
            requireSameKindOfOnboarding(prepared, attempt);
            requireNotExpired(prepared);
        } catch (OnboardingRejectedException rejected) {
            if (!command.dryRun()) {
                recordRejection(attempt, rejected);
            }
            retireIfNewKey(prepared, key, command.dryRun(), PENDING_ONLY, rejected);
            throw rejected;
        }
        if (command.dryRun()) {
            return new ImportResult(prepared.keyArn(), null, attempt.operation(), certificate.spkiSha256Hex());
        }
        return prepared.renewal() ? renewAndActivate(command, attempt, certificate)
                : importAndActivate(command, attempt, key, certificate);
    }

    /**
     * Before anything is validated or imported, the key the state names must be the one this preparation created:
     * waiting for its material, tagged for this tenant and this operation, and referenced by no configuration. A
     * state that names any other key (the active one, another tenant's) is rejected and that key is NOT touched.
     */
    private void requireTheKeyOfThisPreparation(OwnKey key, Attempt attempt, boolean dryRun) {
        String problem = whyNotAnOwnNewKey(key, PENDING_ONLY);
        if (problem == null) {
            return;
        }
        OnboardingRejectedException rejected = new OnboardingRejectedException(RejectionReason.POLICY_DENIED,
                "the key named by the state is not the one of this preparation (" + problem + "): nothing was imported");
        if (!dryRun) {
            recordRejection(attempt, rejected);
        }
        throw rejected;
    }

    /**
     * The checks that {@code prepare} ran with are the ones the tenant's certificate was accepted under: {@code import}
     * must not run with laxer or different ones. The key of the preparation is left as it is, so that the operator can
     * repeat the import with the right policy. A state without a policy summary (an old one, or one edited by hand) says
     * nothing about the checks it was prepared with, so it counts as prepared with the strictest ones: production.
     */
    private void requireNoLaxerPolicyThanPrepare(PreparedOnboarding prepared, ImportCommand command, Attempt attempt) {
        String problem = prepared.policy() == null
                ? (command.policy().production() ? null : "the state has no policy summary, so it counts as prepared "
                        + "with the production checks, and import runs without them")
                : prepared.policy().whyNotCoveredBy(command.policy().summary());
        if (problem == null) {
            return;
        }
        OnboardingRejectedException rejected = new OnboardingRejectedException(RejectionReason.POLICY_DENIED,
                "the policy of import is laxer than or different from the one of prepare (" + problem + ")");
        if (!command.dryRun()) {
            recordRejection(attempt, rejected);
        }
        throw rejected;
    }

    private void retireIfNewKey(PreparedOnboarding prepared, OwnKey key, boolean dryRun, Set<KeyState> allowed,
                                Throwable cause) {
        // A renewal created nothing: the key it names is the active one and is never touched.
        if (!dryRun && !prepared.renewal()) {
            retireOwnNewKey(key, allowed, cause);
        }
    }

    private void requireNotExpired(PreparedOnboarding prepared) {
        if (!prepared.renewal() && !clock.instant().isBefore(prepared.importTokenExpiresAt())) {
            throw new OnboardingRejectedException(RejectionReason.POLICY_DENIED, "the import token expired at "
                    + prepared.importTokenExpiresAt() + ": run prepare again");
        }
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
        UUID configurationId;
        try {
            requireExistingKeyIsTheCertificates(attempt, certificate);
            configurationId = store.inTransaction(tx -> activate(tx, attempt, prepared, certificate));
        } catch (OnboardingRejectedException rejected) {
            recordRejection(attempt, rejected);
            throw rejected;
        }
        markImported(command);
        requireTheKeyIsEnabled(attempt.tenant, prepared.keyArn());
        return new ImportResult(prepared.keyArn(), configurationId, attempt.operation(), certificate.spkiSha256Hex());
    }

    /**
     * After the commit the key must be the enabled one: if it is not, the tenant is configured with a key that cannot
     * sign, and the operator must know at once. Nothing is undone: the commit stands, and that key is not touched.
     */
    private void requireTheKeyIsEnabled(String tenant, String keyArn) {
        KeyState state;
        try {
            state = kms.describeKeyState(keyArn);
        } catch (RuntimeException e) {
            log.error("The import of tenant '{}' was committed but the state of its KMS key {} could not be read: {}",
                    tenant, KeyRefs.forLog(keyArn), e.toString());
            throw new OnboardingFailedException("the import of tenant '" + tenant + "' was committed but the state of its "
                    + "KMS key could not be read: check that the key is enabled", e);
        }
        if (state != KeyState.ENABLED) {
            log.error("The import of tenant '{}' was committed but its KMS key {} is {}, not ENABLED", tenant,
                    KeyRefs.forLog(keyArn), state);
            throw new OnboardingFailedException("the import of tenant '" + tenant + "' was committed but its KMS key is "
                    + state + ", not ENABLED: the tenant cannot sign until that is fixed");
        }
    }

    /** After the commit: a failure here cannot undo the change, and the key checks refuse a repeated import anyway. */
    private void markImported(ImportCommand command) {
        if (command.artifacts() == null) {
            return;
        }
        try {
            command.artifacts().markImported(command.prepared(), clock.instant());
        } catch (RuntimeException e) {
            log.error("The import of tenant '{}' was committed but its state file could not be marked as consumed: {}",
                    command.prepared().tenant(), e.toString());
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
        Instant startedAt = clock.instant();
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
        OwnKey key = OwnKey.of(prepared);
        String problem = whyNotAnOwnNewKey(key, PENDING_ONLY, state);
        if (problem != null) {
            OnboardingRejectedException rejected = new OnboardingRejectedException(RejectionReason.POLICY_DENIED,
                    "the key is not discarded (" + problem + ")");
            if (!command.dryRun()) {
                recordDiscardEvent(prepared, Result.DENIED, rejected.getReason(), startedAt, rejected);
            }
            throw rejected;
        }
        if (command.dryRun()) {
            return new DiscardResult(prepared.keyArn(), DiscardOutcome.WOULD_DISCARD);
        }
        retireVerifiedKey(key);
        command.artifacts().markDiscarded(prepared, clock.instant());
        recordDiscardEvent(prepared, Result.SUCCESS, null, startedAt, null);
        return new DiscardResult(prepared.keyArn(), DiscardOutcome.DISCARDED);
    }

    /**
     * A discard is a retirement of a key and is audited, in a transaction of its own because nothing in the database
     * changes: denied when it was refused, a success when the key was retired. A failure to record it never undoes or
     * fails the discard; it is logged and, for a refusal, added to the rejection as suppressed.
     *
     * @param refusal the rejection to add a recording failure to; {@code null} for a success
     */
    private void recordDiscardEvent(PreparedOnboarding prepared, Result result, RejectionReason reason, Instant startedAt,
                                    OnboardingRejectedException refusal) {
        try {
            Instant now = clock.instant();
            store.recordInOwnTransaction(SigningConfigurationChanged.retire(prepared.tenant(), result, reason,
                    identity.callerArn(), Duration.between(startedAt, now), now, prepared.operationId()));
        } catch (RuntimeException e) {
            log.error("The {} discard of tenant '{}' could not be recorded: {}", result.catalogName(), prepared.tenant(),
                    e.toString());
            if (refusal != null) {
                refusal.addSuppressed(e);
            }
        }
    }

    private static final Set<KeyState> PENDING_ONLY = EnumSet.of(KeyState.PENDING_IMPORT);
    /** After this run's own {@code ImportKeyMaterial} succeeded the key is enabled. */
    private static final Set<KeyState> JUST_IMPORTED = EnumSet.of(KeyState.ENABLED);

    /**
     * The one check before anything destroys a key: it is in a state this operation can have left it in, it carries
     * the tags of this preparation (so it is not another tenant's, and not the active key of anyone), and no signing
     * configuration of any tenant references it.
     *
     * @return what is wrong, or {@code null} if the key is the new key of this preparation
     */
    private String whyNotAnOwnNewKey(OwnKey key, Set<KeyState> allowedStates) {
        return whyNotAnOwnNewKey(key, allowedStates, kms.describeKeyState(key.arn()));
    }

    private String whyNotAnOwnNewKey(OwnKey key, Set<KeyState> allowedStates, KeyState state) {
        if (!allowedStates.contains(state)) {
            return "the key is " + state + ", not " + allowedStates
                    + (state == KeyState.ENABLED || state == KeyState.DISABLED ? ": its key material is imported" : "");
        }
        Map<String, String> tags = kms.listTags(key.arn());
        if (!key.operationId().equals(tags.get("operationId")) || !key.tenant().equals(tags.get("Tenant"))) {
            return "its tags are not those of this preparation";
        }
        if (store.isKeyReferenced(key.arn(), false)) {
            return "a signing configuration references the key";
        }
        return null;
    }

    /** Disables the key if it can be, schedules its deletion and deletes its alias if that points to it. */
    private void retireVerifiedKey(OwnKey key) {
        try {
            kms.disableKey(key.arn());
        } catch (RuntimeException e) {
            log.debug("DisableKey of {} was not applied (a key waiting for its material cannot be disabled): {}",
                    KeyRefs.forLog(key.arn()), e.toString());
        }
        kms.scheduleKeyDeletion(key.arn(), pendingDeletionDays);
        deleteAliasIfItIsTheKeys(key);
    }

    /** The alias comes from a file: it is only deleted if it resolves to this very key. */
    private void deleteAliasIfItIsTheKeys(OwnKey key) {
        if (key.alias() == null) {
            return;
        }
        try {
            if (kms.resolveKeyArn(key.alias()).filter(key.arn()::equals).isPresent()) {
                kms.deleteAlias(key.alias());
            } else {
                log.warn("The alias {} does not point to the key {}: it is left alone", key.alias(),
                        KeyRefs.forLog(key.arn()));
            }
        } catch (RuntimeException e) {
            log.warn("The key {} is scheduled for deletion but its alias {} could not be deleted: {}",
                    KeyRefs.forLog(key.arn()), key.alias(), e.toString());
        }
    }

    /**
     * Compensation: the new key that an onboarding created and did not complete is disabled and scheduled for
     * deletion, but only after checking that it still is that key. If it is not (the state names another key, a
     * configuration references it, KMS cannot be read) it is not touched, and the operator is told to look at it.
     */
    private void retireOwnNewKey(OwnKey key, Set<KeyState> allowedStates, Throwable cause) {
        String problem;
        try {
            problem = whyNotAnOwnNewKey(key, allowedStates);
        } catch (RuntimeException e) {
            log.error("The KMS key {} could not be checked and is NOT touched: check it by hand ({})",
                    KeyRefs.forLog(key.arn()), e.toString());
            cause.addSuppressed(e);
            return;
        }
        if (problem != null) {
            log.error("The KMS key {} is NOT touched: {}. Check it by hand.", KeyRefs.forLog(key.arn()), problem);
            return;
        }
        try {
            retireVerifiedKey(key);
            log.warn("The KMS key {} was not put into service: it is disabled and scheduled for deletion",
                    KeyRefs.forLog(key.arn()));
        } catch (RuntimeException e) {
            log.error("The KMS key {} was not put into service and its deletion could not be scheduled: "
                    + "disable it and schedule its deletion by hand", KeyRefs.forLog(key.arn()));
            cause.addSuppressed(e);
        }
    }

    /**
     * From the {@code ImportKeyMaterial} call on, any failure disables and schedules the deletion of the key.
     * Nothing after the commit of the transaction may throw: it would discard a key that is already active.
     */
    private ImportResult importAndActivate(ImportCommand command, Attempt attempt, OwnKey key,
                                           ValidatedOwnKeyCertificate certificate) {
        PreparedOnboarding prepared = command.prepared();
        UUID configurationId;
        try {
            kms.importKeyMaterial(prepared.keyArn(), command.importToken(), command.encryptedKeyMaterial());
            attempt.keyMaterialImported = true;
            if (!MessageDigest.isEqual(kms.getPublicKey(prepared.keyArn()), certificate.spkiDer())) {
                throw new OnboardingRejectedException(RejectionReason.INVALID_KEY,
                        "the public key of the imported KMS key is not the public key of the certificate");
            }
            configurationId = store.inTransaction(tx -> activate(tx, attempt, prepared, certificate));
        } catch (OnboardingRejectedException rejected) {
            retireOwnNewKey(key, statesToRetire(attempt), rejected);
            recordRejection(attempt, rejected);
            throw rejected;
        } catch (CommitOutcomeUnknownException unknown) {
            log.error("The outcome of the commit is unknown: the KMS key {} may be the active one and was NOT "
                    + "disabled. Check tenant_signing_config before doing anything else.",
                    KeyRefs.forLog(prepared.keyArn()));
            throw unknown;
        } catch (RuntimeException failure) {
            retireOwnNewKey(key, statesToRetire(attempt), failure);
            throw failure;
        }
        markImported(command);
        requireTheKeyIsEnabled(attempt.tenant, prepared.keyArn());
        return new ImportResult(prepared.keyArn(), configurationId, attempt.operation(), certificate.spkiSha256Hex());
    }

    /** The key is enabled only if THIS run imported its material; otherwise it must still be waiting for it. */
    private static Set<KeyState> statesToRetire(Attempt attempt) {
        return attempt.keyMaterialImported ? JUST_IMPORTED : PENDING_ONLY;
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

    private static String defaultAlias(String tenant, String operationId) {
        return "alias/own-key-" + tenant + "-" + operationId;
    }

    private static void requireTenantId(String tenant) {
        if (tenant == null || !TENANT_ID.matcher(tenant).matches()) {
            throw new OnboardingUsageException("the tenant id must be lowercase letters, digits, '-' or '_', "
                    + "start with a letter and have at most 63 characters");
        }
        if (RESERVED_TENANT.equals(tenant)) {
            // The Issuer takes "unknown" for a request without tenant: a key tagged Tenant=unknown must not exist.
            throw new OnboardingUsageException("'" + RESERVED_TENANT + "' is not a tenant id the tool accepts");
        }
    }
}
