package es.in2.issuer.backend.shared.infrastructure.config;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryMetadata;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

import java.io.Closeable;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Wraps the auto-configured R2DBC {@code ConnectionFactory} (which already includes
 * connection pooling) with tenant context injection for PostgreSQL Row-Level Security.
 *
 * <p>Uses a {@link BeanPostProcessor} to wrap the bean <em>after</em> Spring Boot's
 * R2DBC auto-configuration has created it, avoiding the
 * {@code @ConditionalOnMissingBean(ConnectionFactory.class)} conflict that would
 * prevent the auto-configured {@code ConnectionFactory} from being created.
 *
 * <p>On every {@code create()} call — i.e., each time a connection is borrowed from
 * the pool — this wrapper executes {@code SET app.current_tenant = '...'} to configure
 * the RLS policy before any application query runs.
 *
 * <p>The tenant identifier is read from Reactor Context (key: {@code tenantDomain}),
 * populated by {@link TenantDomainWebFilter} from the {@code X-Tenant-Domain} header.
 * When no tenant is present (system operations, schedulers), the wildcard {@code '*'}
 * is used, which the RLS policy allows to access all rows.
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
public class TenantAwareConnectionFactoryDecorator {

    static final String SYSTEM_TENANT = "*";

    @Bean
    static BeanPostProcessor tenantAwareConnectionFactoryPostProcessor() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if ("connectionFactory".equals(beanName) && bean instanceof ConnectionFactory cf) {
                    log.info("Wrapping ConnectionFactory '{}' with tenant-aware decorator", beanName);
                    return new TenantAwareConnectionFactory(cf);
                }
                return bean;
            }
        };
    }

    static class TenantAwareConnectionFactory implements ConnectionFactory, Closeable {

        private final ConnectionFactory delegate;

        TenantAwareConnectionFactory(ConnectionFactory delegate) {
            this.delegate = delegate;
        }

        @Override
        public Publisher<? extends Connection> create() {
            return Mono.deferContextual(ctx -> {
                String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
                return Mono.from(delegate.create())
                        .flatMap(connection -> setTenant(connection, tenant));
            });
        }

        @Override
        public ConnectionFactoryMetadata getMetadata() {
            return delegate.getMetadata();
        }

        /**
         * Delegates shutdown to the underlying pool so that Spring's
         * {@code destroyMethod="dispose"} on the original bean works correctly.
         */
        public void dispose() {
            if (delegate instanceof Closeable c) {
                try {
                    c.close();
                } catch (Exception e) {
                    log.warn("Error closing delegate ConnectionFactory: {}", e.getMessage());
                }
            }
        }

        @Override
        public void close() {
            dispose();
        }

        private Mono<Connection> setTenant(Connection connection, String tenant) {
            return Mono.from(connection.createStatement(
                            "SET app.current_tenant = '" + sanitize(tenant) + "'")
                    .execute())
                    .then(Mono.just(connection))
                    .doOnSuccess(c -> log.trace("R2DBC tenant set to '{}'", tenant))
                    .onErrorResume(e -> {
                        log.warn("Failed to set tenant on connection: {}", e.getMessage());
                        return Mono.from(connection.close()).then(Mono.error(e));
                    });
        }

        /**
         * Sanitizes the tenant identifier to prevent SQL injection.
         * Only allows alphanumeric, hyphens, underscores, dots and the wildcard '*'.
         */
        private String sanitize(String tenant) {
            if (SYSTEM_TENANT.equals(tenant)) {
                return SYSTEM_TENANT;
            }
            if (tenant == null || !tenant.matches("^[a-zA-Z0-9._-]+$")) {
                log.warn("Invalid tenant identifier rejected: {}", tenant);
                return "__invalid__";
            }
            return tenant;
        }
    }
}
