package es.in2.issuer.backend.shared.domain.model.requestcontrol;

/**
 * The operations of the management APIs that have their own volume limit (EUD-269): each one is
 * counted apart, so a burst of reads never uses up the issuances of the same requester.
 *
 * <ul>
 *   <li>{@link #ISSUANCE}: issuance API, FR-09 of EUD-254.</li>
 *   <li>{@link #REVOCATION}: revocation API, FR-07 of EUD-247.</li>
 *   <li>{@link #SEARCH}: search by identifier of the query API, §5 of EUD-255.</li>
 *   <li>{@link #READ}: list and detail of the query API, §5 of EUD-255.</li>
 * </ul>
 */
public enum ApiOperation {

    ISSUANCE("issuance"),
    REVOCATION("revocation"),
    SEARCH("search"),
    READ("read");

    private final String key;

    ApiOperation(String key) {
        this.key = key;
    }

    /** Name used in the configuration keys, the logs and the metrics. */
    public String key() {
        return key;
    }
}
