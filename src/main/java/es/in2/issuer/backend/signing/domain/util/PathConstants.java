package es.in2.issuer.backend.signing.domain.util;

public class PathConstants {

    private PathConstants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String AUTHORIZE_PATH = "/csc/v2/credentials/authorize";
    public static final String SIGN_HASH_PATH = "/csc/v2/signatures/signHash";
    public static final String SIGN_DOC_PATH = "/csc/v2/signatures/signDoc";
    public static final String INFO_PATH = "/csc/v2/credentials/info";
    public static final String LIST_PATH  = "/csc/v2/credentials/list";
}
