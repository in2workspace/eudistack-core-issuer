package es.in2.issuer.backend.shared.infrastructure.repository;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor
public class CacheStore<T> implements TransientStore<T> {

    private final Cache<String, T> cache;
    private final long expiryDuration;
    private final TimeUnit timeUnit;

    private static final long DEFAULT_MAX_SIZE = 10_000;

    public CacheStore(long expiryDuration, TimeUnit timeUnit) {
        this(expiryDuration, timeUnit, DEFAULT_MAX_SIZE);
    }

    public CacheStore(long expiryDuration, TimeUnit timeUnit, long maxSize) {
        this.expiryDuration = expiryDuration;
        this.timeUnit = timeUnit;
        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(expiryDuration, timeUnit)
                .maximumSize(maxSize)
                .concurrencyLevel(Runtime.getRuntime().availableProcessors())
                .build();
    }

    @Override
    public Mono<T> get(String key) {
        T value = cache.getIfPresent(key);
        if (value != null) {
            return Mono.just(value);
        } else {
            return Mono.error(new NoSuchElementException("Value is not present."));
        }
    }

    @Override
    public Mono<T> getAndDelete(String key) {
        return Mono.fromCallable(() -> {
            T value = cache.asMap().remove(key);
            if (value == null) {
                throw new NoSuchElementException("Value is not present.");
            }
            return value;
        });
    }

    @Override
    public Mono<Void> delete(String key) {
        return Mono.fromRunnable(() -> cache.invalidate(key));
    }

    @Override
    public Mono<String> add(String key, T value) {
        return Mono.fromCallable(() -> {
            if (key != null && !key.trim().isEmpty() && value != null) {
                cache.put(key, value);
                return key;
            }
            return null;  // Return null to indicate that nothing was added
        }).filter(Objects::nonNull);  // Only emit if the result is non-null
    }

    /**
     * Gets the cache expiry duration in seconds.
     *
     * @return the cache expiry duration in seconds
     */
    @Override
    public Mono<Integer> getExpiryInSeconds() {
        return Mono.fromSupplier(() -> {
            long seconds = timeUnit.toSeconds(expiryDuration);
            if (seconds > Integer.MAX_VALUE) {
                throw new IllegalStateException("Expiry duration exceeds maximum integer value.");
            }
            return (int) seconds;
        });
    }

}
