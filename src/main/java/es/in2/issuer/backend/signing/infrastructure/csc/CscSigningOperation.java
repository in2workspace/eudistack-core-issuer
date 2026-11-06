package es.in2.issuer.backend.signing.infrastructure.csc;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/** The CSC operation of a QTSP configuration ({@code signingOperation}): only the QTSP provider reads it. */
public enum CscSigningOperation {

    SIGN_HASH("sign-hash"),
    SIGN_DOC("sign-doc");

    private static final Map<String, CscSigningOperation> BY_VALUE = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(CscSigningOperation::value, Function.identity()));

    private final String value;

    CscSigningOperation(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static CscSigningOperation fromValue(String value) {

        CscSigningOperation operation = BY_VALUE.get(value);

        if (operation == null) {
            throw new IllegalArgumentException(
                    "Unsupported CSC signing type: " + value
            );
        }

        return operation;
    }
}
