package es.in2.issuer.backend.signing.infrastructure.csc.v2;

public final class CscV2Paths {

    private CscV2Paths() {
        throw new IllegalStateException("Utility class");
    }

    public static final String AUTHORIZE = "/csc/v2/credentials/authorize";
    public static final String SIGN_HASH = "/csc/v2/signatures/signHash";
    public static final String SIGN_DOC  = "/csc/v2/signatures/signDoc";
    public static final String INFO      = "/csc/v2/credentials/info";
    public static final String LIST      = "/csc/v2/credentials/list";
}
