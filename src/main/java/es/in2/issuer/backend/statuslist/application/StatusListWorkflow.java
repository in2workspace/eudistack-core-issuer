package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListWorkflow {

    private final StatusListProvider statusListProvider;

    @Observed(name = "statuslist.allocate-entry", contextualName = "statuslist-allocate-entry")
    public Mono<StatusListEntry> allocateEntry(StatusPurpose purpose, StatusListFormat format, String procedureId, String token) {
        log.info(
                "action=allocateStatusListEntry status=started purpose={} format={} procedureId={}",
                purpose, format, procedureId
        );
        requireNonNullParam(purpose, "purpose");
        requireNonNullParam(format, "format");

        return statusListProvider.allocateEntry(purpose, format, procedureId, token)
                .doOnSuccess(entry -> log.info(
                        "action=allocateStatusListEntry status=completed purpose={} format={} procedureId={} listId={} idx={}",
                        purpose, format, procedureId,
                        extractListId(entry), entry.statusListIndex()
                ))
                .doOnError(e -> log.warn(
                        "action=allocateStatusListEntry status=failed purpose={} format={} procedureId={} error={}",
                        purpose, format, procedureId, e.toString()
                ));
    }

    @Observed(name = "statuslist.get-signed-credential", contextualName = "statuslist-get-signed-credential")
    public Mono<String> getSignedStatusListCredential(Long listId) {
        requireNonNullParam(listId, "listId");
        return statusListProvider.getSignedStatusListCredential(listId);
    }


    private String extractListId(StatusListEntry entry) {
        String cred = entry.statusListCredential();
        if (cred == null) return "unknown";
        int lastSlash = cred.lastIndexOf('/');
        return lastSlash >= 0 ? cred.substring(lastSlash + 1) : "unknown";
    }
}

