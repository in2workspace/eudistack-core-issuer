package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.signing.domain.exception.SigningConfigurationChangedException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * One signing configuration per request (EUD-289 M4). A request reads the tenant's configuration twice:
 * to put the issuer in the payload ({@code IssuerFactory}) and to sign it. Within {@link #run} the first
 * read is kept in the Reactor context and the second one reuses it, so the payload and the signature
 * always come from the same certificate.
 *
 * <p>When signing finds that the configuration changed (an own key replaced while this instance still
 * had the old one in cache), {@code TenantSigningConfigService} fails with
 * {@link SigningConfigurationChangedException} and {@link #run} runs the work once more, from its first
 * read. The work must therefore be safe to repeat up to the signature.
 */
@Slf4j
public final class SigningConfigScope {

    private static final String CONTEXT_KEY = SigningConfigScope.class.getName();

    private SigningConfigScope() {}

    /**
     * Runs {@code work} with one signing configuration per tenant. Inside another scope it joins that
     * one, and the outer scope is the one that repeats the work.
     */
    public static <T> Mono<T> run(Supplier<Mono<T>> work) {
        return Mono.deferContextual(ctx -> {
            if (ctx.hasKey(CONTEXT_KEY)) {
                return Mono.defer(work);
            }
            return scoped(work).onErrorResume(SigningConfigScope::isConfigurationChanged, error -> {
                log.info("Signing configuration changed during the request, running it again with the new one");
                return scoped(work);
            });
        });
    }

    /** The configurations pinned by the current request, if it runs within {@link #run}. */
    public static Optional<Pins> current(ContextView ctx) {
        return ctx.getOrEmpty(CONTEXT_KEY);
    }

    private static <T> Mono<T> scoped(Supplier<Mono<T>> work) {
        return Mono.defer(work).contextWrite(ctx -> ctx.put(CONTEXT_KEY, new Pins()));
    }

    /** Callers wrap signing errors (for example into {@code RemoteSignatureException}), so the cause chain is walked. */
    static boolean isConfigurationChanged(Throwable throwable) {
        Set<Throwable> seen = new HashSet<>();
        Throwable current = throwable;
        while (current != null && seen.add(current)) {
            if (current instanceof SigningConfigurationChangedException) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    /** The configuration each tenant had at its first read within one run of the work. */
    public static final class Pins {

        private final Map<String, ActiveSigningConfig> byTenant = new ConcurrentHashMap<>();

        public Optional<ActiveSigningConfig> get(String tenant) {
            return Optional.ofNullable(byTenant.get(tenant));
        }

        /** Pins {@code config} unless the tenant already has one, and returns the one that stays pinned. */
        public ActiveSigningConfig pinIfAbsent(String tenant, ActiveSigningConfig config) {
            ActiveSigningConfig previous = byTenant.putIfAbsent(tenant, config);
            return previous == null ? config : previous;
        }
    }
}
