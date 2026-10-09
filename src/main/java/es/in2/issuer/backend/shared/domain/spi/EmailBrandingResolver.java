package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import reactor.core.publisher.Mono;

/**
 * Resolves the email branding of the tenant held in the Reactor context, falling back to the
 * default (EUDIStack) branding for any item the tenant does not define. It does not depend on
 * a web request, so it works identically from schedulers.
 */
public interface EmailBrandingResolver {

    Mono<EmailBranding> resolve();
}
