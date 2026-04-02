package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Routes signing requests to the CSC operation configured for the active QTSP.
 * The {@code signingOperation} field in {@link RemoteSignatureDto} determines
 * whether {@code sign-hash} or {@code sign-doc} is used.
 */
@Slf4j
@RequiredArgsConstructor
public class DelegatingSigningProvider implements SigningProvider {

    public static final String OP_SIGN_HASH = "sign-hash";
    public static final String OP_SIGN_DOC = "sign-doc";

    private final RuntimeSigningConfig runtimeSigningConfig;
    private final Map<String, SigningProvider> providersByOperation;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        RemoteSignatureDto cfg = runtimeSigningConfig.getRemoteSignature();
        if (cfg == null) {
            return Mono.error(new SigningException(
                    "No remote signature configuration available. " +
                    "Push config via PUT /internal/signing/config or configure signing.remote-signature in application.yml"));
        }

        String operation = cfg.signingOperation();
        if (operation == null || operation.isBlank()) {
            return Mono.error(new SigningException(
                    "signingOperation is required in the QTSP configuration. " +
                    "Set it to 'sign-hash' or 'sign-doc'."));
        }

        operation = operation.trim().toLowerCase();
        SigningProvider delegate = providersByOperation.get(operation);

        if (delegate == null) {
            return Mono.error(new SigningException(
                    "No SigningProvider for operation '" + operation + "'. " +
                            "Available: " + providersByOperation.keySet()
            ));
        }

        log.info("Signing via provider='{}' operation='{}' type='{}'",
                runtimeSigningConfig.getProvider(), operation, request.type());
        return delegate.sign(request);
    }
}
