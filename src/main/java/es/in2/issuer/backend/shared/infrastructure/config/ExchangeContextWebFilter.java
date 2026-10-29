package es.in2.issuer.backend.shared.infrastructure.config;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.reactive.ServerWebExchangeContextFilter;

/**
 * Puts the exchange in the Reactor context of every request, so the error handling can set the
 * Content-Type of the Problem Details it writes on the management API (ErrorResponseFactory, EUD-307). First in the chain,
 * so every filter and handler below sees it.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ExchangeContextWebFilter extends ServerWebExchangeContextFilter {
}
