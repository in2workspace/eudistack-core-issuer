package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException.Violation;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/** Body of the PATCH that enables or disables an entry: {@code {"enabled": true}} and nothing else. */
@Getter
@Setter
public class CatalogEntryEnabledRequest extends UnknownFieldsCollector {

    private Boolean enabled;

    /**
     * @return whether to enable the entry
     * @throws CatalogConfigurationException (BAD_REQUEST) if {@code enabled} is missing or the body has
     *         any other field
     */
    public boolean requireEnabled() {
        List<Violation> violations = new ArrayList<>();
        if (enabled == null) {
            violations.add(new Violation("enabled", "is required"));
        }
        unknownFields().forEach(name -> violations.add(new Violation(name, "is not a known field")));
        if (!violations.isEmpty()) {
            throw CatalogConfigurationException.badRequest(violations);
        }
        return enabled;
    }
}
