package es.in2.issuer.backend.shared.domain.model.catalog;

/** Request to create a catalog entry: the schema it is for and its configuration. */
public record CreateCatalogEntryCommand(String schemaUri, CatalogConfigurationInput configuration) {
}
