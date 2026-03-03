package es.in2.issuer.backend.oidc4vci.infrastructure.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(Oid4vciProfileProperties.class)
public class Oid4vciProfileConfig {
}
