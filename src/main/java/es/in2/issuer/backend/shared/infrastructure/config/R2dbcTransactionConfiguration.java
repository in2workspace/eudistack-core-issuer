package es.in2.issuer.backend.shared.infrastructure.config;

import io.r2dbc.spi.ConnectionFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.transaction.ReactiveTransactionManager;
import org.springframework.transaction.reactive.TransactionalOperator;

/**
 * Enables reactive transactions for R2DBC. Prior to EUD-72 the Issuer performed
 * no multi-statement atomic writes, so no reactive transaction manager was wired.
 *
 * <p>{@code updateCatalog()} needs an atomic {@code deleteAll + insert} replace:
 * without a transaction, a failure after {@code deleteAll} would leave the tenant
 * with zero rows, which the read side interprets as "all types enabled"
 * (empty = all) — silently re-opening the whole catalog. The transaction guarantees
 * rollback to the previous state.
 *
 * <p>The transactional connection is borrowed once via {@code ConnectionFactory.create()},
 * which is where {@code TenantAwareConnectionFactoryDecorator} sets the per-tenant
 * {@code search_path}; therefore every statement in the transaction runs against the
 * correct tenant schema (covered by {@code CredentialCatalogTransactionalIT}).
 *
 * <p>Only the programmatic {@link TransactionalOperator} is used, so
 * {@code @EnableTransactionManagement} (needed only for declarative {@code @Transactional})
 * is intentionally omitted.
 */
@Configuration
public class R2dbcTransactionConfiguration {

    @Bean
    public ReactiveTransactionManager transactionManager(ConnectionFactory connectionFactory) {
        return new R2dbcTransactionManager(connectionFactory);
    }

    @Bean
    public TransactionalOperator transactionalOperator(ReactiveTransactionManager transactionManager) {
        return TransactionalOperator.create(transactionManager);
    }
}
