package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import reactor.core.publisher.Mono;

/**
 * Resolves the email branding of the tenant held in the Reactor context. The support and
 * knowledge-base links fall back to the default ones; images and social links are shown only
 * when the tenant defines them. It does not depend on a web request, so it works identically
 * from schedulers.
 */
public interface EmailBrandingResolver {

    Mono<EmailBranding> resolve();
}
