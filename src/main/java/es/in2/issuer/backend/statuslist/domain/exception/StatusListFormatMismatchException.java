package es.in2.issuer.backend.statuslist.domain.exception;

import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;

/**
 * An issuance already holds a status list allocation on a list whose serialization format differs
 * from the one the current credential format requires. Emitting the credential anyway would embed a
 * status reference resolving to the wrong document type, so allocation fails loudly instead.
 */
public class StatusListFormatMismatchException extends RuntimeException {

    public StatusListFormatMismatchException(String issuanceId, Long statusListId,
                                            StatusListFormat storedFormat, StatusListFormat requestedFormat) {
        super("Status list format mismatch for issuanceId=%s statusListId=%d: allocated as %s, requested %s"
                .formatted(issuanceId, statusListId, storedFormat.value(), requestedFormat.value()));
    }
}
