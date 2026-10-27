package es.in2.issuer.backend.signing.infrastructure.onboarding.audit;

import com.eudistack.auditoria.autoconfigure.AuditContextAutoConfiguration;
import com.eudistack.auditoria.autoconfigure.AuditOutboxAutoConfiguration;
import com.eudistack.auditoria.autoconfigure.AuditPublisherAutoConfiguration;
import com.eudistack.auditoria.jdbc.JdbcAuditOutboxSchema;
import com.eudistack.auditoria.jdbc.JdbcOutboxStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Import;

import javax.sql.DataSource;

/**
 * The minimal Spring context of the onboarding tool when its audit events go to the outbox: a non-web application
 * that imports only the starter's own auto-configurations for the properties, the context accessor and the
 * publisher. It does not scan, nor enable auto-configuration, so nothing of the Issuer (R2DBC, Flyway, WebFlux, its
 * beans) is created. The dispatcher auto-configuration is not imported: the tool never sends events, the Issuer does.
 *
 * <p>Deliberately not annotated with {@code @Configuration}: the Issuer scans {@code es.in2.issuer.backend}, and a
 * scanned copy of this class would try to build the outbox inside the Issuer. It is registered explicitly by
 * {@link OutboxAuditSinkFactory}, and {@code @Import} with {@code @Bean} methods is enough for that.
 *
 * <p>The starter configures its JDBC outbox only for servlet applications, so the two beans of
 * {@code AuditOutboxJdbcAutoConfiguration} are declared here exactly as it declares them. The {@link DataSource}
 * is the tool's own, registered by {@link OutboxAuditSinkFactory}, so that the outbox joins the transactions of the
 * tool.
 */
@Import({AuditOutboxAutoConfiguration.class, AuditContextAutoConfiguration.class,
        AuditPublisherAutoConfiguration.class})
class OutboxAuditConfiguration {

    @Bean
    JdbcAuditOutboxSchema auditOutboxSchema(DataSource dataSource) {
        return new JdbcAuditOutboxSchema(dataSource);
    }

    @Bean
    @DependsOn("auditOutboxSchema")
    JdbcOutboxStore auditOutboxStore(DataSource dataSource) {
        return new JdbcOutboxStore(dataSource);
    }
}
