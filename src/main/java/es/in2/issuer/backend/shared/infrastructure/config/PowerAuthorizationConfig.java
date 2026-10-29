package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.port.AuthorizationMatrixProvider;
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.policy.service.impl.PowerAuthorizationServiceImpl;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Wires the decision point (EUD-253), which is domain code without Spring annotations. */
@Configuration
public class PowerAuthorizationConfig {

    @Bean
    public PowerAuthorizationService powerAuthorizationService(AuthorizationMatrixProvider matrixProvider,
                                                               CallerProvider callerProvider,
                                                               TenantCredentialProfileService tenantCredentialProfileService,
                                                               AuditService auditService,
                                                               ObjectMapper objectMapper) {
        return new PowerAuthorizationServiceImpl(matrixProvider, callerProvider, tenantCredentialProfileService,
                auditService, objectMapper);
    }
}
