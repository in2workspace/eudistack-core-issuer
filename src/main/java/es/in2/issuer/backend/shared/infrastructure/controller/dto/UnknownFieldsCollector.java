package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonAnySetter;

import java.util.ArrayList;
import java.util.List;

/**
 * Base of the request bodies the Attestation Catalogue contract closes ({@code additionalProperties:
 * false}). The global mapper ignores unknown properties ({@code FAIL_ON_UNKNOWN_PROPERTIES=false}) and
 * {@code @JsonIgnoreProperties(ignoreUnknown = false)} falls back to it, so a closed body collects the
 * names it does not know here and the validator turns each into a violation.
 *
 * <p>The accessor is not named {@code getUnknownFields}: a bean getter of a collection would let Jackson
 * treat {@code unknownFields} as a property of the body.
 */
public abstract class UnknownFieldsCollector {

    private final List<String> unknownFields = new ArrayList<>();

    @JsonAnySetter
    public void collectUnknownField(String name, Object value) {
        unknownFields.add(name);
    }

    public List<String> unknownFields() {
        return List.copyOf(unknownFields);
    }
}
