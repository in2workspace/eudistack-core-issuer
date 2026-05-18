package es.in2.issuer.backend.signing.infrastructure.csc.v1;

public final class CscV1Paths {

    private CscV1Paths() {
        throw new IllegalStateException("Utility class");
    }

    public static final String AUTHORIZE = "/csc/v1/credentials/authorize";
    public static final String SIGN_HASH = "/csc/v1/signatures/signHash";
    public static final String SIGN_DOC  = "/csc/v1/signatures/signDoc";
    public static final String INFO      = "/csc/v1/credentials/info";
    public static final String LIST      = "/csc/v1/credentials/list";
}
