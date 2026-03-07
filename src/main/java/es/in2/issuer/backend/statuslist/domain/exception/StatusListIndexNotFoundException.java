package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * Thrown when there is no status_list_index mapping for a given issuance.
 */
public class StatusListIndexNotFoundException extends RuntimeException {

    private final String issuanceId;

    public StatusListIndexNotFoundException(String issuanceId) {
        super("Status list index not found for issuance");
        this.issuanceId = issuanceId;
    }

    public String getIssuanceId() {
        return issuanceId;
    }
}

