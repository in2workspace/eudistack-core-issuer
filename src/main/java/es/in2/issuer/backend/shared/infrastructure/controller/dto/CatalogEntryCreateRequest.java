package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.shared.domain.model.catalog.CreateCatalogEntryCommand;
import lombok.Getter;
import lombok.Setter;

/** {@code CatalogEntryCreate} of the Attestation Catalogue contract: a configuration plus the schema it is for. */
@Getter
@Setter
public class CatalogEntryCreateRequest extends CatalogEntryConfigurationRequest {

    @JsonProperty("schema_uri")
    private String schemaUri;

    public CreateCatalogEntryCommand toCommand() {
        return new CreateCatalogEntryCommand(schemaUri, toStrictInput());
    }
}
