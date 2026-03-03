package es.in2.issuer.backend.backoffice.infrastructure.config.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationManager customAuthenticationManager;
    private final InternalCORSConfig internalCORSConfig;

    @Bean
    @Primary
    public ReactiveAuthenticationManager primaryAuthenticationManager() {
        return customAuthenticationManager;
    }

    @Bean
    public AuthenticationWebFilter customAuthenticationWebFilter(ProblemAuthenticationEntryPoint entryPoint) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(customAuthenticationManager);
        log.debug("customAuthenticationWebFilter - inside");

        authenticationWebFilter.setRequiresAuthenticationMatcher(
                ServerWebExchangeMatchers.pathMatchers(
                        // OID4VCI / VCI paths
                        VCI_ISSUANCES_PATH,
                        OAUTH_TOKEN_PATH,
                        OID4VCI_CREDENTIAL_PATH,
                        OID4VCI_DEFERRED_CREDENTIAL_PATH,
                        OID4VCI_NOTIFICATION_PATH,
                        // Backoffice paths (migrated from internalFilterChain)
                        BACKOFFICE_PATH,
                        STATUS_LIST_PATH,
                        SIGNING_PROVIDERS_PATH,
                        SIGNING_CONFIG_PATH)
        );

        authenticationWebFilter.setServerAuthenticationConverter(new DualTokenServerAuthenticationConverter());
        authenticationWebFilter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(entryPoint));
        return authenticationWebFilter;
    }

    @Bean
    @Order(1)
    public SecurityWebFilterChain unifiedFilterChain(
            ServerHttpSecurity http,
            ProblemAuthenticationEntryPoint entryPoint,
            ProblemAccessDeniedHandler deniedH
    ) {
        log.debug("unifiedFilterChain - inside");

        http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(
                        // Public OID4VCI paths
                        CORS_OID4VCI_PATH,
                        VCI_PATH,
                        WELL_KNOWN_PATH,
                        OAUTH_PATH,
                        // Backoffice paths (migrated from internalFilterChain)
                        BACKOFFICE_PATH,
                        STATUS_LIST_PATH,
                        SIGNING_PROVIDERS_PATH,
                        SIGNING_CONFIG_PATH,
                        HEALTH_PATH,
                        PROMETHEUS_PATH,
                        SPRINGDOC_PATH
                ))
                .cors(cors -> cors.configurationSource(internalCORSConfig.defaultCorsConfigurationSource()))
                .authorizeExchange(exchange -> exchange
                        // Public endpoints (no auth)
                        .pathMatchers(HttpMethod.GET,
                                CORS_CREDENTIAL_OFFER_PATH,
                                CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH,
                                AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH,
                                OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH,
                                JWKS_PATH,
                                HEALTH_PATH,
                                PROMETHEUS_PATH,
                                SPRINGDOC_PATH,
                                STATUS_LIST_PATH,
                                SIGNING_PROVIDERS_PATH,
                                BACKOFFICE_STATUS_CREDENTIALS
                        ).permitAll()
                        .pathMatchers(HttpMethod.POST, OAUTH_TOKEN_PATH).permitAll()
                        .pathMatchers(HttpMethod.POST, OID4VCI_PAR_PATH).permitAll()
                        .pathMatchers(HttpMethod.GET, OID4VCI_AUTHORIZE_PATH).permitAll()
                        .pathMatchers(HttpMethod.POST, OID4VCI_NONCE_PATH).permitAll()
                        .pathMatchers(HttpMethod.PUT, SIGNING_CONFIG_PATH).permitAll()
                        // Authenticated endpoints (all go through CustomAuthenticationManager)
                        .anyExchange().authenticated()
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .addFilterAt(customAuthenticationWebFilter(entryPoint), SecurityWebFiltersOrder.AUTHENTICATION)
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedH)
                );
        log.debug("unifiedFilterChain - build");
        return http.build();
    }

}