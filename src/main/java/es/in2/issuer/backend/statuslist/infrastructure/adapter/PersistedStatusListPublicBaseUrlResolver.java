package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.util.JwtUtils;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListIndexNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListNotFoundException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListPublicBaseUrlNotResolvableException;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.service.StatusListPublicBaseUrlResolver;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusList;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.STATUS_LIST_BASE;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.TOKEN_STATUS_LIST_BASE;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

/**
 * Implements {@link StatusListPublicBaseUrlResolver} (AD-2): derives the public
 * issuer base URL a status list was originally signed against directly from the
 * already-persisted, already-signed list — the only source that is structurally
 * incapable of drifting from the invariant that re-signing must reuse the exact
 * same base URL the list's {@code id}/{@code sub} was published under.
 * <p>
 * Fail-closed by construction: any step that cannot be completed (no allocation
 * for the issuance, no list, no signed payload, unparseable payload, or a
 * claim value that does not end with the expected {@code <base>/<listId>} suffix)
 * throws rather than falling back to a guessed or configured value.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PersistedStatusListPublicBaseUrlResolver implements StatusListPublicBaseUrlResolver {

    private final StatusListIndexRepository statusListIndexRepository;
    private final StatusListRepository statusListRepository;
    private final JwtUtils jwtUtils;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<String> resolve(String issuanceId) {
        requireNonNullParam(issuanceId, "issuanceId");
        log.debug("method=resolve step=START issuanceId={}", issuanceId);

        return statusListIndexRepository.findByIssuanceId(UUID.fromString(issuanceId))
                .switchIfEmpty(Mono.error(new StatusListIndexNotFoundException(issuanceId)))
                .flatMap(listIndex -> statusListRepository.findById(listIndex.statusListId())
                        .switchIfEmpty(Mono.error(new StatusListNotFoundException(listIndex.statusListId()))))
                .flatMap(this::derivePublicBaseUrl)
                .doOnSuccess(url -> log.debug("method=resolve step=END issuanceId={} publicIssuerBaseUrl={}", issuanceId, url))
                .doOnError(e -> log.warn("method=resolve step=ERROR issuanceId={} error={}", issuanceId, e.toString()));
    }

    private Mono<String> derivePublicBaseUrl(StatusList list) {
        return Mono.fromCallable(() -> {
            String signedCredential = list.signedCredential();
            if (signedCredential == null || signedCredential.isBlank()) {
                throw new StatusListPublicBaseUrlNotResolvableException(
                        "Status list " + list.id() + " has no signed credential yet");
            }

            StatusListFormat format = StatusListFormat.fromValue(list.format());
            JsonNode payload = parsePayload(list.id(), signedCredential);
            String claimName = (format == StatusListFormat.TOKEN_JWT) ? "sub" : "id";
            JsonNode claim = payload.get(claimName);
            if (claim == null || !claim.isTextual() || claim.asText().isBlank()) {
                throw new StatusListPublicBaseUrlNotResolvableException(
                        "Status list " + list.id() + " signed payload has no usable '" + claimName + "' claim");
            }

            String base = (format == StatusListFormat.TOKEN_JWT) ? TOKEN_STATUS_LIST_BASE : STATUS_LIST_BASE;
            String suffix = base + "/" + list.id();
            String claimValue = claim.asText();
            if (!claimValue.endsWith(suffix)) {
                throw new StatusListPublicBaseUrlNotResolvableException(
                        "Status list " + list.id() + " claim '" + claimName + "'=" + claimValue
                                + " does not end with the expected suffix " + suffix);
            }
            return claimValue.substring(0, claimValue.length() - suffix.length());
        });
    }

    private JsonNode parsePayload(Long listId, String signedCredential) {
        try {
            String payloadJson = jwtUtils.decodePayload(signedCredential);
            return objectMapper.readTree(payloadJson);
        } catch (Exception e) {
            throw new StatusListPublicBaseUrlNotResolvableException(
                    "Status list " + listId + " signed credential payload could not be parsed: " + e.getMessage());
        }
    }
}
