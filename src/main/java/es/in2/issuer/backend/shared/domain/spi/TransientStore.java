package es.in2.issuer.backend.shared.domain.spi;

import reactor.core.publisher.Mono;

public interface TransientStore<T> {
    Mono<T> get(String key);
    Mono<Void> delete(String key);
    Mono<String> add(String key, T value);

    /**
     * Stores {@code value} under {@code key} in one atomic step and emits the value it replaced,
     * or completes empty if there was none. Two concurrent calls on the same key never both see
     * the same previous value, so a caller can safely retire whatever it replaced.
     */
    Mono<T> replace(String key, T value);
    Mono<Integer> getExpiryInSeconds();
}
