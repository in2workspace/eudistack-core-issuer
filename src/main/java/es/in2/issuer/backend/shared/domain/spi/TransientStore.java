package es.in2.issuer.backend.shared.domain.spi;

import reactor.core.publisher.Mono;

public interface TransientStore<T> {
    Mono<T> get(String key);
    Mono<T> getAndDelete(String key);
    Mono<Void> delete(String key);
    Mono<String> add(String key, T value);
    Mono<Integer> getExpiryInSeconds();
}
