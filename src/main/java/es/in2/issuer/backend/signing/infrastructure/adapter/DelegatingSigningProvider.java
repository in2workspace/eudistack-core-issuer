package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
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
 * Routes signing requests to the CSC operation configured for the active tenant's QTSP.
 * Reads signing config per-tenant from DB (via TenantSigningConfigService) with fallback
 * to the global default QTSP (mock).
 */
@Slf4j
@RequiredArgsConstructor
public class DelegatingSigningProvider implements SigningProvider {

    public static final String OP_SIGN_HASH = "sign-hash";
    public static final String OP_SIGN_DOC = "sign-doc";

    private final RuntimeSigningConfig runtimeSigningConfig;
    private final Map<String, SigningProvider> providersByOperation;
    private final TenantSigningConfigService tenantSigningConfigService;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return tenantSigningConfigService.getRemoteSignature()
                .switchIfEmpty(Mono.defer(() -> {
                    RemoteSignatureDto globalCfg = runtimeSigningConfig.getRemoteSignature();
                    return globalCfg != null ? Mono.just(globalCfg) : Mono.error(new SigningException(
                            "No remote signature configuration available for this tenant. " +
                            "Configure tenant_signing_config in DB or set global default in application.yml"));
                }))
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
                    return delegate.sign(request);
                });
    }
}
