package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.entities.TenantConfig;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantConfigRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
public class TenantConfigServiceImpl implements TenantConfigService {

    private final TenantConfigRepository tenantConfigRepository;

    public TenantConfigServiceImpl(TenantConfigRepository tenantConfigRepository) {
        this.tenantConfigRepository = tenantConfigRepository;
    }

    @Override
    public Mono<String> getString(String key) {
        return tenantConfigRepository.findByConfigKey(key)
                .map(TenantConfig::configValue)
                .doOnNext(value -> log.trace("Tenant config '{}' = '{}'", key, value));
    }

    @Override
    public Mono<String> getStringOrDefault(String key, String defaultValue) {
        return getString(key)
                .defaultIfEmpty(defaultValue);
    }

}
