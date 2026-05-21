package es.in2.issuer.backend.dome.infrastructure.config;

import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(KeyMigrationProperties.class)
public class KeyMigrationConfiguration {
}

