package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

/**
 * Database side of the onboarding tool: the tenant registry, the signing configuration of each tenant
 * and the SPKI reservation. The tool is a separate process, so this is its own access to the database,
 * not the Issuer's.
 */
public interface OwnKeyStorePort {

    /**
     * A tenant of {@code public.tenant_registry}.
     *
     * @param active              the registry says the tenant is active
     * @param schemaProvisioned   the tenant's Issuer schema exists and holds {@code tenant_signing_config}
     * @param activeModality      modality of the tenant's active signing configuration; {@code null} if it has none
     * @param activeConfigurationId id of that configuration; {@code null} if it has none
     * @param activeKmsKeyRef     KMS key of that configuration when it is an own-key one; {@code null} otherwise
     */
    record RegisteredTenant(String id, boolean active, boolean schemaProvisioned, SigningModality activeModality,
                            UUID activeConfigurationId, String activeKmsKeyRef) {

        public RegisteredTenant(String id, boolean active, boolean schemaProvisioned, SigningModality activeModality) {
            this(id, active, schemaProvisioned, activeModality, null, null);
        }
    }

    /** A reservation of an SPKI hash: the tenant that holds it and the configuration it was made for. */
    record SpkiReservation(String tenantId, UUID configurationId) {}

    Optional<RegisteredTenant> findTenant(String tenantId);

    /** Ids of the tenants the registry marks active, in the order the tool reconciles them. */
    List<String> findActiveTenants();

    /** @return the reservation of this SPKI hash, if any (for any tenant, the same one included) */
    Optional<SpkiReservation> findSpkiReservation(byte[] spkiSha256);

    /**
     * Whether the KMS key is referenced by a signing configuration of any tenant.
     *
     * @param activeOnly {@code true} to look only at active rows, {@code false} at rows of every status
     */
    boolean isKeyReferenced(String kmsKeyRef, boolean activeOnly);

    /** Own-key rows of the tenant withdrawn for longer than {@code grace} whose KMS key is not marked yet; no lock. */
    List<WithdrawnOwnKey> findWithdrawnOwnKeysPendingKms(String tenantId, Duration grace);

    /**
     * Runs {@code work} in one database transaction: it commits when {@code work} returns and rolls back
     * when it throws, rethrowing. Events staged with {@link ConfigurationTransaction#stage} are part of it.
     */
    <T> T inTransaction(Function<ConfigurationTransaction, T> work);

    /**
     * Records an event in a transaction of its own, for an onboarding that was rejected: staged in the
     * business transaction it would be rolled back with it.
     */
    void recordInOwnTransaction(SigningConfigurationChanged event);

    /**
     * Takes, without waiting, the lock that serialises the runs of one onboarding operation: while it is held, no
     * other run of the same operation (on this database) can take it. It is held for the whole run, not for one
     * transaction, and ends when it is closed or the process dies.
     *
     * @return the lock, or empty if another run holds it
     * @throws OnboardingFailedException if the lock cannot be asked for: the run must not go on without it
     */
    Optional<OperationLock> tryLockOperation(String operationId);

    /** A lock of {@link #tryLockOperation}; closing it releases it and never throws. */
    interface OperationLock extends AutoCloseable {

        /**
         * Whether the lock is still held by this run. It can be lost without the run knowing it (the session that held it
         * ended: a cut connection, a server timeout, a failover); after that, another run of the same operation may have
         * taken it. Never throws: if it cannot be shown to be held, it is not.
         */
        boolean isHeld();

        @Override
        void close();
    }

    /** A withdrawn own-key row whose KMS key still has to be retired. */
    record WithdrawnOwnKey(UUID id, String tenantId, String kmsKeyRef) {}

    /** The active configuration of a tenant. */
    record ActiveConfiguration(UUID id, SigningModality modality, String kmsKeyRef) {

        public ActiveConfiguration(UUID id, SigningModality modality) {
            this(id, modality, null);
        }
    }

    /** The own-key configuration that becomes active. */
    record NewOwnKeyConfiguration(String kmsKeyRef, List<String> certificateChain) {}

    /** What the tool does inside one transaction, on the schema of a tenant. */
    interface ConfigurationTransaction {

        /** {@code SELECT ... FOR UPDATE} of the active row; also serialises onboardings of the same tenant. */
        Optional<ActiveConfiguration> lockActiveConfiguration(String tenantId);

        /**
         * The row becomes {@code withdrawn}. A QTSP row loses its four secret fields
         * ({@code credentialPwd}, {@code clientSecret}, {@code accessKey}, {@code credentialId}) and keeps
         * the rest. An own-key row keeps its SPKI reservation until {@link #markKeyRetired}: the key still
         * exists in KMS, and its public key must not be onboarded for another tenant. A withdrawn row is never
         * active again.
         */
        void withdraw(String tenantId, ActiveConfiguration configuration, String withdrawnBy);

        /** Inserts the new {@code active} own-key row, activated now by {@code activatedBy}; returns its id. */
        UUID activateOwnKey(String tenantId, NewOwnKeyConfiguration configuration, String activatedBy);

        /**
         * Reserves the SPKI for the tenant's configuration.
         *
         * @throws OnboardingRejectedException {@code KEY_IN_USE}
         *         if the hash is already reserved
         */
        void reserveSpki(byte[] spkiSha256, String tenantId, UUID configurationId);

        /** The next withdrawn own-key row past the grace whose KMS key is not marked yet, locked with SKIP LOCKED. */
        Optional<WithdrawnOwnKey> lockNextWithdrawnOwnKey(String tenantId, Duration grace,
                                                          Set<UUID> excluding);

        /**
         * Marks the row as handled ({@code own_key_deleted_at}) because its KMS key was retired, so the row is not
         * selected again. It also releases the SPKI reservation of the row, if it holds one, in the same transaction.
         */
        void markKeyRetired(String tenantId, WithdrawnOwnKey key);

        /**
         * Marks the row as handled ({@code own_key_deleted_at}) because its KMS key is still referenced by an active
         * configuration and must not be retired, so the row is not selected again. The SPKI reservation of the row is
         * NOT released: the key still signs, so its public key must stay reserved for its tenant.
         */
        void markKeyStillInUse(String tenantId, WithdrawnOwnKey key);

        /** Stages the event in this transaction: it is only published if the transaction commits. */
        void stage(SigningConfigurationChanged event);
    }
}
