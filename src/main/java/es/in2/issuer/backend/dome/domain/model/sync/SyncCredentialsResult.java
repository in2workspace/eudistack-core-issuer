package es.in2.issuer.backend.dome.domain.model.sync;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.util.Constants;
import java.util.List;

/**
 * Represents the final result containing the user's pre-existing credentials
 * to be returned to the wallet during the auto-recovery payload.
 *
 * @param credentials The list of pre-existing verifiable credentials in JSON format.
 * @param format      The format type of the credentials payload.
 */
public record SyncCredentialsResult (
        List<JsonNode> credentials,
        String format
) {
    public SyncCredentialsResult(List<JsonNode> credentials) {
        this(credentials, Constants.SYNC_CREDENTIALS_FORMAT_VC_LIST);
    }
}
