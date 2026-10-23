package es.in2.issuer.backend.signing.domain.model;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Key of every {@link es.in2.issuer.backend.signing.domain.spi.SigningProvider}: the two CSC
 * operations of the QTSP modality ({@code signingOperation} of its configuration) and KMS for the
 * own-key modality (EUD-289).
 */
public enum SigningProviderType {

    CSC_SIGN_HASH("sign-hash"),
    CSC_SIGN_DOC("sign-doc"),
    AWS_KMS("aws-kms");

    private static final Map<String, SigningProviderType> CSC_OPERATIONS = Arrays.stream(values())
            .filter(SigningProviderType::isCscOperation)
            .collect(Collectors.toUnmodifiableMap(SigningProviderType::value, Function.identity()));

    private final String value;

    SigningProviderType(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    /**
     * The CSC operation named by a QTSP configuration. Only the CSC values are accepted, so a QTSP
     * configuration can never be routed to the KMS provider.
     */
    public static SigningProviderType fromCscOperation(String value) {

        SigningProviderType provider = CSC_OPERATIONS.get(value);

        if (provider == null) {
            throw new IllegalArgumentException(
                    "Unsupported CSC signing type: " + value
            );
        }

        return provider;
    }

    private boolean isCscOperation() {
        return this != AWS_KMS;
    }
}
