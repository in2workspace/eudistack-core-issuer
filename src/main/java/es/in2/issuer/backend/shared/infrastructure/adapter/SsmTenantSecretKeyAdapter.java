package es.in2.issuer.backend.shared.infrastructure.adapter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.exception.TenantSecretKeyUnavailableException;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprinter;
import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
import es.in2.issuer.backend.shared.infrastructure.config.properties.SearchIdentifierProperties;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;

import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * {@link TenantSecretKeyPort} over Parameter Store (AD-3 and §6 of the EUD-254 design): {@code GetParameter} with
 * decryption of the tenant's {@code SecureString}, 32 random bytes in base64.
 *
 * <p>Keys are kept in a Caffeine cache bounded in size and time (SEC-27): at most {@value #MAX_TENANTS} tenants, an
 * hour after being read. A key that is not found or cannot be read is not cached, so the next request reads again.
 * The client is built on the first read, on a scheduler that may block (resolving the region may query the instance
 * metadata), like the KMS one. Neither the key nor the parameter value is ever logged.
 */
@Slf4j
public class SsmTenantSecretKeyAdapter implements TenantSecretKeyPort {

    static final int MAX_TENANTS = 1000;
    static final Duration CACHE_TTL = Duration.ofHours(1);
    static final Duration CALL_TIMEOUT = Duration.ofSeconds(5);
    /** The tenant goes into a parameter name: only the characters a tenant schema name has. */
    private static final Pattern TENANT = Pattern.compile("^[a-z0-9_-]{1,63}$");

    private final Supplier<SsmAsyncClient> clientFactory;
    private final String keyParameter;
    private final AtomicReference<SsmAsyncClient> client = new AtomicReference<>();
    private final Cache<String, byte[]> keys = Caffeine.newBuilder()
            .maximumSize(MAX_TENANTS)
            .expireAfterWrite(CACHE_TTL)
            .build();

    /** @param keyParameter the name of the parameter, with {@link SearchIdentifierProperties#TENANT_PLACEHOLDER}; blank if none */
    public SsmTenantSecretKeyAdapter(Supplier<SsmAsyncClient> clientFactory, String keyParameter) {
        this.clientFactory = clientFactory;
        this.keyParameter = keyParameter == null ? "" : keyParameter.strip();
    }

    @Override
    public Mono<byte[]> keyOf(String tenant) {
        return Mono.defer(() -> {
            if (tenant == null || !TENANT.matcher(tenant).matches()) {
                return Mono.error(new TenantSecretKeyUnavailableException("Not a tenant whose secret key can be read"));
            }
            byte[] cached = keys.getIfPresent(tenant);
            if (cached != null) {
                return Mono.just(cached.clone());
            }
            if (keyParameter.isEmpty()) {
                return Mono.error(new TenantSecretKeyUnavailableException(
                        "No parameter of the tenant secret keys is configured (issuer.search-identifiers.key-parameter)"));
            }
            String name = keyParameter.replace(SearchIdentifierProperties.TENANT_PLACEHOLDER, tenant);
            return client()
                    .flatMap(ssm -> Mono.fromFuture(() -> ssm.getParameter(GetParameterRequest.builder()
                            .name(name)
                            .withDecryption(true)
                            .build())))
                    .timeout(CALL_TIMEOUT)
                    .map(response -> decode(tenant, response.parameter().value()))
                    .doOnNext(key -> keys.put(tenant, key.clone()))
                    .onErrorMap(e -> !(e instanceof TenantSecretKeyUnavailableException), e -> unavailable(tenant, e));
        });
    }

    private Mono<SsmAsyncClient> client() {
        SsmAsyncClient built = client.get();
        if (built != null) {
            return Mono.just(built);
        }
        return Mono.fromCallable(() -> {
                    SsmAsyncClient created = clientFactory.get();
                    client.set(created);
                    return created;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .timeout(CALL_TIMEOUT);
    }

    private static byte[] decode(String tenant, String value) {
        byte[] key;
        try {
            key = Base64.getDecoder().decode(value == null ? "" : value.strip());
        } catch (IllegalArgumentException e) {
            throw new TenantSecretKeyUnavailableException("The secret key of tenant '" + tenant + "' is not base64");
        }
        if (key.length < SearchIdentifierFingerprinter.FINGERPRINT_BYTES) {
            throw new TenantSecretKeyUnavailableException("The secret key of tenant '" + tenant + "' has fewer than "
                    + SearchIdentifierFingerprinter.FINGERPRINT_BYTES + " bytes");
        }
        return key;
    }

    private static TenantSecretKeyUnavailableException unavailable(String tenant, Throwable cause) {
        Throwable root = cause.getCause() != null ? cause.getCause() : cause;
        if (root instanceof ParameterNotFoundException) {
            log.warn("No secret key is configured for tenant '{}' in Parameter Store", tenant);
            return new TenantSecretKeyUnavailableException("No secret key is configured for tenant '" + tenant + "'");
        }
        log.warn("The secret key of tenant '{}' cannot be read from Parameter Store: {}", tenant,
                root.getClass().getSimpleName());
        return new TenantSecretKeyUnavailableException("The secret key of tenant '" + tenant + "' cannot be read",
                root);
    }
}
