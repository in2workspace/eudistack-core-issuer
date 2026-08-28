package es.in2.issuer.backend.apiclient.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class ApiClientSecurityConfig {

    @Bean
    public PasswordEncoder apiClientPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
