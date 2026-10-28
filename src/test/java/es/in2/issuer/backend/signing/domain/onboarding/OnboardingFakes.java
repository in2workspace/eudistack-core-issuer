package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort;
import es.in2.issuer.backend.signing.domain.spi.OnboardingArtifactsPort;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

/** In-memory collaborators of the onboarding use cases: they record what was asked and can be made to fail. */
final class OnboardingFakes {

    private OnboardingFakes() {}

    /** A KMS that records every call, in order, as {@code operation} or {@code operation:detail}. */
    static final class FakeKms implements KmsKeyAdministrationPort {

        static final String KEY_ARN = "arn:aws:kms:eu-west-1:000000000000:key/11111111-2222-3333-4444-555555555555";

        final List<String> calls = new ArrayList<>();
        final Map<String, KeyState> states = new HashMap<>();
        final Map<String, RuntimeException> failures = new HashMap<>();
        byte[] wrappingPublicKey = {1, 2, 3};
        byte[] importToken = {9, 8, 7};
        Instant tokenValidTo = Instant.parse("2026-10-28T12:00:00Z");
        byte[] publicKey;
        Map<String, String> tags = new HashMap<>();
        final Map<String, String> aliases = new HashMap<>();
        /** Run at the start of the call they name: a way to change the world under a run. */
        Runnable beforeImportKeyMaterial = () -> { };
        Runnable duringGetPublicKey = () -> { };

        private void recordCall(String call) {
            calls.add(call);
            RuntimeException failure = failures.get(call.contains(":") ? call.substring(0, call.indexOf(':')) : call);
            if (failure != null) {
                throw failure;
            }
        }

        @Override
        public String createKey(String tenant, String operationId) {
            recordCall("createKey:" + tenant + ":" + operationId);
            states.put(KEY_ARN, KeyState.PENDING_IMPORT);
            tags.put("Tenant", tenant);
            tags.put("operationId", operationId);
            return KEY_ARN;
        }

        @Override
        public void createAlias(String alias, String keyArn) {
            recordCall("createAlias:" + alias);
            aliases.put(alias, keyArn);
        }

        @Override
        public ImportParameters getParametersForImport(String keyArn) {
            recordCall("getParametersForImport");
            return new ImportParameters(wrappingPublicKey, importToken, tokenValidTo);
        }

        @Override
        public void importKeyMaterial(String keyArn, byte[] token, byte[] encryptedKeyMaterial) {
            beforeImportKeyMaterial.run();
            recordCall("importKeyMaterial");
            states.put(keyArn, KeyState.ENABLED);
        }

        @Override
        public byte[] getPublicKey(String keyArn) {
            duringGetPublicKey.run();
            recordCall("getPublicKey");
            return publicKey;
        }

        @Override
        public KeyState describeKeyState(String keyArn) {
            recordCall("describeKey:" + keyArn);
            return states.getOrDefault(keyArn, KeyState.ENABLED);
        }

        @Override
        public java.util.Optional<String> resolveKeyArn(String keyIdOrAlias) {
            recordCall("resolveKeyArn:" + keyIdOrAlias);
            return java.util.Optional.ofNullable(aliases.get(keyIdOrAlias));
        }

        @Override
        public Map<String, String> listTags(String keyArn) {
            recordCall("listTags:" + keyArn);
            return tags;
        }

        @Override
        public void deleteAlias(String alias) {
            recordCall("deleteAlias:" + alias);
            aliases.remove(alias);
        }

        @Override
        public void disableKey(String keyArn) {
            recordCall("disableKey:" + keyArn);
        }

        @Override
        public void scheduleKeyDeletion(String keyArn, int pendingWindowDays) {
            recordCall("scheduleKeyDeletion:" + keyArn + ":" + pendingWindowDays);
        }

        List<String> calls(String operation) {
            return calls.stream().filter(call -> call.equals(operation) || call.startsWith(operation + ":")).toList();
        }
    }

    /** An in-memory database: changes of a transaction are applied only when it commits. */
    static final class FakeStore implements OwnKeyStorePort {

        final Map<String, RegisteredTenant> tenants = new HashMap<>();
        final Map<String, SpkiReservation> reservations = new HashMap<>();
        final Set<String> activeKeyRefs = new HashSet<>();
        final Set<String> otherKeyRefs = new HashSet<>();
        /** Key reference to the id of the active row of the tenant being reconciled that uses it. */
        final Map<String, UUID> sameTenantActiveRows = new HashMap<>();
        final List<String> committedOperations = new ArrayList<>();
        final List<SigningConfigurationChanged> committedEvents = new ArrayList<>();
        final List<SigningConfigurationChanged> eventsInOwnTransaction = new ArrayList<>();
        final List<WithdrawnOwnKey> withdrawn = new ArrayList<>();
        final List<NewOwnKeyConfiguration> activated = new ArrayList<>();
        final Set<UUID> retired = new HashSet<>();
        final Set<String> tenantsWithoutSchema = new HashSet<>();
        final Set<String> lockedOperations = java.util.concurrent.ConcurrentHashMap.newKeySet();
        /** Operations whose lock was lost while a run held it (its session ended). */
        final Set<String> lostLocks = java.util.concurrent.ConcurrentHashMap.newKeySet();
        ActiveConfiguration active;
        RuntimeException failure;
        RuntimeException failureRecordingEvent;
        RuntimeException referenceCheckFailure;
        Runnable onTransactionStart = () -> { };
        int transactions;

        @Override
        public Optional<OperationLock> tryLockOperation(String operationId) {
            if (!lockedOperations.add(operationId)) {
                return Optional.empty();
            }
            return Optional.of(new OperationLock() {
                @Override
                public boolean isHeld() {
                    return !lostLocks.contains(operationId);
                }

                @Override
                public void close() {
                    lockedOperations.remove(operationId);
                }
            });
        }

        @Override
        public Optional<RegisteredTenant> findTenant(String tenantId) {
            return Optional.ofNullable(tenants.get(tenantId));
        }

        @Override
        public List<String> findActiveTenants() {
            return tenants.values().stream().filter(RegisteredTenant::active).map(RegisteredTenant::id).toList();
        }

        /** Reserves the hash (hexadecimal) for the tenant, on a configuration that is not the active one. */
        void reserve(String spkiSha256Hex, String tenantId) {
            reservations.put(spkiSha256Hex, new SpkiReservation(tenantId, UUID.randomUUID()));
        }

        @Override
        public Optional<SpkiReservation> findSpkiReservation(byte[] spkiSha256) {
            return Optional.ofNullable(reservations.get(HexFormat.of().formatHex(spkiSha256)));
        }

        @Override
        public boolean isKeyReferenced(String kmsKeyRef, boolean activeOnly) {
            if (referenceCheckFailure != null) {
                throw referenceCheckFailure;
            }
            return activeKeyRefs.contains(kmsKeyRef) || (!activeOnly && otherKeyRefs.contains(kmsKeyRef));
        }

        @Override
        public List<WithdrawnOwnKey> findWithdrawnOwnKeysPendingKms(String tenantId, Duration grace) {
            return withdrawn.stream().filter(row -> row.tenantId().equals(tenantId) && !retired.contains(row.id())).toList();
        }

        @Override
        public <T> T inTransaction(Function<ConfigurationTransaction, T> work) {
            transactions++;
            onTransactionStart.run();
            FakeTransaction transaction = new FakeTransaction();
            T result = work.apply(transaction);
            if (failure != null) {
                throw failure;
            }
            committedOperations.addAll(transaction.operations);
            committedEvents.addAll(transaction.events);
            activated.addAll(transaction.activatedHere);
            retired.addAll(transaction.retiredHere);
            retired.addAll(transaction.keptReservation);
            reservations.values().removeIf(reservation -> transaction.retiredHere.contains(reservation.configurationId()));
            transaction.reservationMoves.forEach((from, to) -> reservations.replaceAll((hash, reservation) ->
                    reservation.configurationId().equals(from)
                            ? new SpkiReservation(reservation.tenantId(), to) : reservation));
            return result;
        }

        @Override
        public void recordInOwnTransaction(SigningConfigurationChanged event) {
            if (failureRecordingEvent != null) {
                throw failureRecordingEvent;
            }
            eventsInOwnTransaction.add(event);
        }

        private final class FakeTransaction implements ConfigurationTransaction {

            private final List<String> operations = new ArrayList<>();
            private final List<SigningConfigurationChanged> events = new ArrayList<>();
            private final List<NewOwnKeyConfiguration> activatedHere = new ArrayList<>();
            private final Set<UUID> retiredHere = new HashSet<>();
            private final Set<UUID> keptReservation = new HashSet<>();
            private final Map<UUID, UUID> reservationMoves = new HashMap<>();

            @Override
            public Optional<ActiveConfiguration> lockActiveConfiguration(String tenantId) {
                operations.add("lockActive:" + tenantId);
                return Optional.ofNullable(active);
            }

            @Override
            public void withdraw(String tenantId, ActiveConfiguration configuration, String withdrawnBy) {
                operations.add("withdraw:" + configuration.modality() + ":" + withdrawnBy);
            }

            @Override
            public UUID activateOwnKey(String tenantId, NewOwnKeyConfiguration configuration, String activatedBy) {
                operations.add("activate:" + configuration.kmsKeyRef() + ":" + activatedBy);
                activatedHere.add(configuration);
                return UUID.fromString("00000000-0000-0000-0000-0000000000aa");
            }

            @Override
            public void reserveSpki(byte[] spkiSha256, String tenantId, UUID configurationId) {
                String hash = HexFormat.of().formatHex(spkiSha256);
                var existing = reservations.get(hash);
                if (existing != null && !retiredHere.contains(existing.configurationId())) {
                    throw new OnboardingRejectedException(RejectionReason.KEY_IN_USE, "reserved in the meantime");
                }
                operations.add("reserve:" + tenantId);
            }

            @Override
            public Optional<WithdrawnOwnKey> lockNextWithdrawnOwnKey(String tenantId, Duration grace, Set<UUID> excluding) {
                if (tenantsWithoutSchema.contains(tenantId)) {
                    throw new OnboardingFailedException("the schema of " + tenantId + " does not exist");
                }
                return withdrawn.stream()
                        .filter(row -> row.tenantId().equals(tenantId) && !retired().contains(row.id())
                                && !excluding.contains(row.id()))
                        .findFirst();
            }

            private Set<UUID> retired() {
                Set<UUID> all = new HashSet<>(FakeStore.this.retired);
                all.addAll(retiredHere);
                all.addAll(keptReservation);
                return all;
            }

            @Override
            public void markKeyRetired(String tenantId, WithdrawnOwnKey key) {
                operations.add("markHandled:" + key.kmsKeyRef());
                // marking a row handled releases the reservation of its configuration
                retiredHere.add(key.id());
            }

            @Override
            public Optional<UUID> markKeyStillInUse(String tenantId, WithdrawnOwnKey key) {
                operations.add("markStillInUse:" + key.kmsKeyRef());
                // handled, but its reservation stays, or passes to the active row of the tenant that uses the key
                keptReservation.add(key.id());
                Optional<UUID> holder = Optional.ofNullable(sameTenantActiveRows.get(key.kmsKeyRef()));
                holder.ifPresent(active -> reservationMoves.put(key.id(), active));
                return holder;
            }

            @Override
            public void stage(SigningConfigurationChanged event) {
                events.add(event);
            }
        }
    }

    static OwnKeyStorePort.RegisteredTenant activeTenant(String id, SigningModality activeModality) {
        return new OwnKeyStorePort.RegisteredTenant(id, true, true, activeModality);
    }

    /** Collects what {@code prepare} writes. */
    static final class RecordingArtifacts implements OnboardingArtifactsPort {

        PreparedOnboarding prepared;
        byte[] wrappingPublicKey;
        byte[] importToken;
        RuntimeException failure;
        RuntimeException markDiscardedFailure;
        PreparedOnboarding discarded;
        PreparedOnboarding imported;
        /** The state as kept now, with its marks; {@code null} until it is marked or set by a test. */
        PreparedOnboarding current;

        @Override
        public void markImported(PreparedOnboarding prepared, Instant importedAt) {
            this.imported = prepared;
            this.current = new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(),
                    prepared.alias(), prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                    prepared.importTokenExpiresAt(), prepared.renewal(), prepared.discardedAt(), importedAt,
                    prepared.policy());
        }

        @Override
        public void markDiscarded(PreparedOnboarding prepared, Instant discardedAt) {
            if (markDiscardedFailure != null) {
                throw markDiscardedFailure;
            }
            this.discarded = prepared;
            this.current = new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(),
                    prepared.alias(), prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                    prepared.importTokenExpiresAt(), prepared.renewal(), discardedAt, prepared.importedAt(),
                    prepared.policy());
        }

        @Override
        public PreparedOnboarding current(PreparedOnboarding prepared) {
            return current != null ? current : prepared;
        }

        @Override
        public void write(PreparedOnboarding prepared, byte[] wrappingPublicKeyDer, byte[] importToken) {
            if (failure != null) {
                throw failure;
            }
            this.prepared = prepared;
            this.wrappingPublicKey = wrappingPublicKeyDer;
            this.importToken = importToken;
        }
    }
}
