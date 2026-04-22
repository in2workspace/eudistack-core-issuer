package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Routes signing requests to the CSC operation configured for the active
 * tenant's QTSP. Reads signing config per-tenant from the database (via
 * {@link TenantSigningConfigService}) and injects it into the {@link
 * SigningRequest} before delegating.
 *
 * <p>There is no global fallback: if {@code tenant_signing_config} has no
 * row for the active tenant, a {@link SigningException} is thrown. Seed
 * the row via {@code seed-tenants[.stg].sql} or via the per-tenant config
 * management service (future EUDI-090).
 */
@Slf4j
@RequiredArgsConstructor
public class DelegatingSigningProvider implements SigningProvider {

    public static final String OP_SIGN_HASH = "sign-hash";
    public static final String OP_SIGN_DOC = "sign-doc";

    private final Map<String, SigningProvider> providersByOperation;
    private final TenantSigningConfigService tenantSigningConfigService;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return tenantSigningConfigService.getRemoteSignature()
                .switchIfEmpty(Mono.error(new SigningException(
                        "No remote signature configuration available for this tenant. " +
                        "Seed tenant_signing_config for the active tenant.")))
                .flatMap(cfg -> {
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
                                "Available: " + providersByOperation.keySet()));
                    }

                    log.info("Signing via operation='{}' type='{}' url='{}'",
                            operation, request.type(), cfg.url());

                    SigningRequest enriched = enrich(request, cfg);
                    return delegate.sign(enriched);
                });
    }

    /**
     * Returns a new {@link SigningRequest} with {@code remoteSignature} set to
     * the tenant-resolved config, preserving all other fields. The field is
     * left untouched if it was already set by an upstream caller.
     */
    private static SigningRequest enrich(SigningRequest original, RemoteSignatureDto cfg) {
        if (original.remoteSignature() != null) {
            return original;
        }
        return SigningRequest.builder()
                .type(original.type())
                .data(original.data())
                .context(original.context())
                .typ(original.typ())
                .remoteSignature(cfg)
                .build();
    }
}
