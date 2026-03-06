package es.in2.issuer.backend.statuslist.infrastructure.adapter;


import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.statuslist.domain.exception.*;
import es.in2.issuer.backend.statuslist.domain.factory.BitstringStatusListCredentialFactory;
import es.in2.issuer.backend.statuslist.domain.factory.TokenStatusListCredentialFactory;
import es.in2.issuer.backend.statuslist.domain.model.StatusListData;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusListIndexData;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.service.impl.BitstringStatusListRevocationService;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import es.in2.issuer.backend.statuslist.domain.util.BitstringEncoder;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusList;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListRepository;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.STATUS_LIST_BASE;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.TOKEN_STATUS_LIST_BASE;
import static es.in2.issuer.backend.statuslist.domain.util.Constants.*;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

/**
 * StatusListProvider implementation supporting both:
 * - W3C BitstringStatusListCredential (BITSTRING_VC)
 * - Token Status List / draft-ietf-oauth-status-list (TOKEN_JWT)
 *
 * Both formats share the same DB tables, index reservation algorithm, and bitstring encoding.
 * They differ in: credential payload structure, signing typ header, and serving endpoint.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BitstringStatusListProvider implements StatusListProvider {

    private final AppConfig appConfig;
    private final StatusListRepository statusListRepository;
    private final StatusListIndexRepository statusListIndexRepository;
    private final BitstringStatusListCredentialFactory bitstringFactory;
    private final TokenStatusListCredentialFactory tokenFactory;
    private final BitstringStatusListRevocationService revocationService;
    private final BitstringStatusListIndexReservation statusListIndexReservationService;
    private final StatusListSigner statusListSigner;
    private final IssuerFactory issuerFactory;

    private final BitstringEncoder encoder = new BitstringEncoder();

    @Override
    public Mono<String> getSignedStatusListCredential(Long listId) {
        requireNonNullParam(listId, "listId");
        log.debug("method=getSignedStatusListCredential step=START listId={}", listId);

        return statusListRepository.findById(listId)
                .switchIfEmpty(Mono.error(new StatusListNotFoundException(listId)))
                .flatMap(row -> {
                    String signed = row.signedCredential();
                    if (signed == null || signed.isBlank()) {
                        return Mono.error(new SignedStatusListCredentialNotAvailableException(listId));
                    }
                    return Mono.just(signed);
                })
                .doOnSuccess(v ->
                        log.debug("method=getSignedStatusListCredential step=END listId={}", listId)
                );
    }

    @Override
    @Observed(name = "statuslist.provider.allocate-entry", contextualName = "statuslist-provider-allocate-entry")
    public Mono<StatusListEntry> allocateEntry(StatusPurpose purpose, StatusListFormat format, String procedureId, String token) {
        requireNonNullParam(purpose, "purpose");
        requireNonNullParam(format, "format");
        requireNonNullParam(procedureId, "procedureId");
        requireNonNullParam(token, TOKEN);

        log.debug("method=allocateEntry step=START purpose={} format={} procedureId={}", purpose, format, procedureId);

        return findExistingAllocation(purpose, format, procedureId)
                .switchIfEmpty(Mono.defer(() -> allocateNewEntry(purpose, format, procedureId, token)))
                .map(entry -> {
                    log.debug(
                            "method=allocateEntry step=END purpose={} format={} procedureId={} statusListId={} idx={}",
                            purpose, format, procedureId, entry.statusListCredential(), entry.statusListIndex()
                    );
                    return entry;
                })
                .doOnError(e -> log.warn(
                        "method=allocateEntry step=ERROR purpose={} format={} procedureId={} error={}",
                        purpose, format, procedureId, e.toString()
                ));
    }

    @Override
    @Observed(name = "statuslist.provider.revoke", contextualName = "statuslist-provider-revoke")
    public Mono<Void> revoke(String procedureId, String token) {
        requireNonNullParam(procedureId, "procedureId");
        requireNonNullParam(token, TOKEN);

        log.debug("method=revoke step=START procedureId={}", procedureId);

        return statusListIndexRepository.findByProcedureId(UUID.fromString(procedureId))
                .switchIfEmpty(Mono.error(new StatusListIndexNotFoundException(procedureId)))
                .flatMap(listIndex -> {
                    log.debug(
                            "method=revoke step=indexResolved procedureId={} statusListId={} idx={}",
                            procedureId, listIndex.statusListId(), listIndex.idx()
                    );
                    return revokeWithRetry(listIndex.statusListId(), listIndex.idx(), token);
                })
                .doOnSuccess(v ->
                        log.debug("method=revoke step=END procedureId={}", procedureId)
                )
                .doOnError(e ->
                        log.warn("method=revoke step=ERROR procedureId={} error={}", procedureId, e.toString())
                );
    }

    // --- Revocation internals ---

    private Mono<Void> revokeWithRetry(Long statusListId, Integer idx, String token) {
        log.debug("method=revokeWithRetry step=START statusListId={} idx={}", statusListId, idx);

        long maxAttempts = 5;

        return Mono.defer(() -> revokeOnce(statusListId, idx, token))
                .retryWhen(
                        Retry.backoff(maxAttempts - 1, Duration.ofMillis(50))
                                .filter(OptimisticUpdateException.class::isInstance)
                                .doBeforeRetry(rs ->
                                    log.debug(
                                        "method=revokeWithRetry retry={} statusListId={} idx={}",
                                            rs.totalRetries() + 1, statusListId, idx
                                )
    )
                )
                .doOnTerminate(() ->
                        log.debug("method=revokeWithRetry step=END statusListId={} idx={}", statusListId, idx)
                );
    }

    private Mono<Void> revokeOnce(Long statusListId, Integer idx, String token) {
        log.debug("method=revokeOnce step=START statusListId={} idx={}", statusListId, idx);

        return resolveRevocationCandidate(statusListId, idx)
                .switchIfEmpty(Mono.defer(() -> {
                    log.debug("method=revokeOnce step=ALREADY_REVOKED statusListId={} idx={}", statusListId, idx);
                    return Mono.empty();
                }))
                .flatMap(row -> {
                    StatusListData domainRow = toDomain(row);
                    StatusListData updatedDomain = revocationService.applyRevocation(domainRow, idx);
                    StatusList updatedRow = toEntity(updatedDomain);

                    return getIssuerAndSignCredential(updatedRow, token)
                            .flatMap(signedJwt ->
                                    statusListRepository.updateSignedAndEncodedIfUnchanged(
                                                    row.id(),
                                                    updatedRow.encodedList(),
                                                    signedJwt,
                                                    row.updatedAt()
                                            )

                            )
                            .flatMap(rowsUpdated -> {
                                if (rowsUpdated == null || rowsUpdated == 0) {
                                    return Mono.error(new OptimisticUpdateException(
                                            "Optimistic lock failure for statusListId=" + statusListId
                                    ));
                                }
                                return Mono.<Void>empty();
                            });
                })
                .doOnTerminate(() ->
                        log.debug("method=revokeOnce step=END statusListId={} idx={}", statusListId, idx)
                );
    }

    // --- Allocation internals ---

    private Mono<StatusListEntry> allocateNewEntry(StatusPurpose purpose, StatusListFormat format, String procedureId, String token) {
        log.debug("method=allocateNewEntry step=START purpose={} format={} procedureId={}", purpose, format, procedureId);

        return pickListForAllocation(purpose, format, token)
                .flatMap(list ->
                        reserveWithNewListFallback(list.id(), purpose, format, procedureId, token)
                )
                .map(reservedIndex -> buildEntry(reservedIndex, format, purpose))
                .doOnSuccess(e ->
                        log.debug("method=allocateNewEntry step=END procedureId={}", procedureId)
                );
    }

    private Mono<StatusList> pickListForAllocation(StatusPurpose purpose, StatusListFormat format, String token) {
        log.debug("method=pickListForAllocation step=START purpose={} format={}", purpose, format);

        long threshold = (long) Math.floor(CAPACITY_BITS * NEW_LIST_THRESHOLD);

        return findOrCreateLatestList(purpose, format, token)
                .flatMap(list ->
                        statusListIndexRepository.countByStatusListId(list.id())
                                .flatMap(count -> {
                                    long safeCount = count == null ? 0 : count;
                                    if (safeCount >= threshold) {
                                        log.debug("method=pickListForAllocation action=createNewList");
                                        return createNewList(purpose, format, token);
                                    }
                                    return Mono.just(list);
                                })
                )
                .doOnSuccess(list ->
                        log.debug("method=pickListForAllocation step=END statusListId={}", list.id())
                );
    }

    private Mono<StatusList> findOrCreateLatestList(StatusPurpose purpose, StatusListFormat format, String token) {
        log.debug("method=findOrCreateLatestList step=START purpose={} format={}", purpose, format);

        return statusListRepository.findLatestByPurposeAndFormat(purpose.value(), format.value())
                .switchIfEmpty(Mono.defer(() -> createNewList(purpose, format, token)))
                .doOnSuccess(list ->
                        log.debug("method=findOrCreateLatestList step=END statusListId={}", list.id())
                );
    }

    public Mono<StatusList> createNewList(StatusPurpose purpose, StatusListFormat format, String token) {
        requireNonNullParam(purpose, "purpose");
        requireNonNullParam(format, "format");
        requireNonNullParam(token, TOKEN);

        log.debug("method=createNewList step=START purpose={} format={}", purpose, format);

        String emptyEncodedList = encoder.createEmptyEncodedList(CAPACITY_BITS);
        Instant now = Instant.now();

        StatusList rowToInsert = new StatusList(
                null,
                purpose.value(),
                format.value(),
                emptyEncodedList,
                null,
                now,
                now
        );

        return statusListRepository.save(rowToInsert)
                .flatMap(saved ->
                        getIssuerAndSignCredential(saved, token)
                                .flatMap(jwt -> persistSignedCredential(saved, jwt))
                                .onErrorResume(ex ->
                                        statusListRepository.deleteById(saved.id())
                                                .doOnSuccess(v -> log.warn(
                                                        "method=createNewList step=ROLLBACK_DELETE statusListId={} cause={}",
                                                        saved.id(), ex.toString()
                                                ))
                                                .onErrorResume(deleteEx -> {
                                                    log.error(
                                                            "method=createNewList step=ROLLBACK_DELETE_FAILED statusListId={} cause={} deleteError={}",
                                                            saved.id(), ex.toString(), deleteEx.toString()
                                                    );
                                                    return Mono.empty();
                                                })
                                                .then(Mono.error(ex))
                                )
                )
                .doOnSuccess(list ->
                        log.debug("method=createNewList step=END statusListId={}", list.id())
                );
    }

    private Mono<StatusList> persistSignedCredential(StatusList saved, String signedJwt) {
        log.debug("method=persistSignedCredential step=START statusListId={}", saved.id());

        return statusListRepository.updateSignedCredential(saved.id(), signedJwt)
                .flatMap(rows -> {
                    if (rows != null && rows == 1) {
                        return Mono.just(saved);
                    }
                    return Mono.error(new StatusListSigningPersistenceException(saved.id()));
                })
                .doOnSuccess(v ->
                        log.debug("method=persistSignedCredential step=END statusListId={}", saved.id())
                );
    }

    private Mono<StatusListEntry> findExistingAllocation(StatusPurpose purpose, StatusListFormat format, String procedureId) {
        log.debug("method=findExistingAllocation step=START procedureId={}", procedureId);
        UUID procedureUuid = UUID.fromString(procedureId);

        return statusListIndexRepository.findByProcedureId(procedureUuid)
                .map(existing -> {
                    log.debug("Found existing allocation in list {}, idx: {}", existing.statusListId(), existing.idx());
                    return buildEntry(toIndexDomain(existing), format, purpose);
                })
                .doOnSuccess(v ->
                        log.debug("method=findExistingAllocation step=END procedureId={} statusListEntry={}", procedureId, v)
                );
    }

    // --- Signing ---

    private Mono<String> getIssuerAndSignCredential(StatusList saved, String token) {
        StatusListFormat fmt = StatusListFormat.fromValue(saved.format());

        return issuerFactory.createSimpleIssuer()
                .flatMap(issuer -> {
                    String listUrl = buildListUrl(saved.id(), fmt);

                    Map<String, Object> payload;
                    String typ;

                    if (fmt == StatusListFormat.TOKEN_JWT) {
                        payload = tokenFactory.buildUnsigned(
                                listUrl, issuer.id(), saved.purpose(), saved.encodedList());
                        typ = TOKEN_STATUS_LIST_JWT_TYP;
                    } else {
                        payload = bitstringFactory.buildUnsigned(
                                listUrl, issuer.id(), saved.purpose(), saved.encodedList());
                        typ = null;
                    }

                    return statusListSigner.sign(payload, token, saved.id(), typ);
                });
    }

    // --- Helpers ---

    private StatusListEntry buildEntry(StatusListIndexData reservedIndex, StatusListFormat format, StatusPurpose purpose) {
        String listUrl = buildListUrl(reservedIndex.statusListId(), format);
        if (format == StatusListFormat.TOKEN_JWT) {
            return tokenFactory.buildStatusListEntry(listUrl, reservedIndex.idx(), purpose);
        }
        return bitstringFactory.buildStatusListEntry(listUrl, reservedIndex.idx(), purpose);
    }

    private String buildListUrl(Long listId, StatusListFormat format) {
        requireNonNullParam(listId, "listId");
        String base = (format == StatusListFormat.TOKEN_JWT) ? TOKEN_STATUS_LIST_BASE : STATUS_LIST_BASE;
        return appConfig.getIssuerInternalUrl() + base + "/" + listId;
    }

    private Mono<StatusList> resolveRevocationCandidate(Long statusListId, Integer idx) {
        requireNonNullParam(statusListId, "statusListId");
        requireNonNullParam(idx, "idx");

        return statusListRepository.findById(statusListId)
                .switchIfEmpty(Mono.error(new StatusListNotFoundException(statusListId)))
                .flatMap(row -> {
                    boolean alreadyRevoked = encoder.getBit(row.encodedList(), idx);
                    if (alreadyRevoked) {
                        log.debug("action=revokeStatusList result=alreadyRevoked statusListId={} idx={}", statusListId, idx);
                        return Mono.empty();
                    }
                    return Mono.just(row);
                });
    }

    private Mono<StatusListIndexData> reserveWithNewListFallback(
            Long statusListId,
            StatusPurpose purpose,
            StatusListFormat format,
            String procedureId,
            String token
    ) {
        return statusListIndexReservationService.reserve(statusListId, procedureId)
                .onErrorResume(
                        IndexReservationExhaustedException.class,
                        ex -> createNewList(purpose, format, token)
                                .flatMap(newList ->
                                        statusListIndexReservationService.reserve(newList.id(), procedureId)
                                )
                );
    }

    // --- Mapping ---

    private static StatusListData toDomain(StatusList entity) {
        return new StatusListData(
                entity.id(),
                entity.purpose(),
                entity.format(),
                entity.encodedList(),
                entity.signedCredential(),
                entity.createdAt(),
                entity.updatedAt()
        );
    }

    private static StatusList toEntity(StatusListData domain) {
        return new StatusList(
                domain.id(),
                domain.purpose(),
                domain.format(),
                domain.encodedList(),
                domain.signedCredential(),
                domain.createdAt(),
                domain.updatedAt()
        );
    }

    private static StatusListIndexData toIndexDomain(StatusListIndex entity) {
        return new StatusListIndexData(
                entity.id(),
                entity.statusListId(),
                entity.idx(),
                entity.procedureId(),
                entity.createdAt()
        );
    }
}
