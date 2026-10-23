package es.in2.issuer.backend.shared.infrastructure.repository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import io.r2dbc.spi.Row;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * R2DBC adapter for {@link CatalogEntryPort} over {@code tenant_credential_profile} (EUD-266).
 *
 * <p>The JSONB columns have no codec in this repository: they are read as text
 * ({@code ::text}) and written with {@code CAST(:x AS jsonb)}, and mapped by hand with Jackson.
 * {@code delivery_modes} is stored as the canonical CSV ({@code NULL} = not filled yet,
 * {@code ''} = empty list).
 */
@Component
@RequiredArgsConstructor
public class CatalogEntryR2dbcAdapter implements CatalogEntryPort {

    private static final String DEFAULT_SEPARATOR = " ";

    private static final String COLUMNS = """
            credential_configuration_id, schema_uri, enabled, delivery_modes,
            validity_default_days, validity_requester_dates, validity_max_days,
            subject_fields::text AS subject_fields, subject_separator,
            search_identifiers::text AS search_identifiers,
            version, created_at, updated_at""";

    private static final String SELECT = "SELECT " + COLUMNS + " FROM tenant_credential_profile";
    private static final String ENABLED = "enabled";

    private final DatabaseClient databaseClient;
    private final ObjectMapper objectMapper;

    @Override
    public Flux<CatalogEntry> findAll() {
        return databaseClient.sql(SELECT + " ORDER BY credential_configuration_id")
                .map((row, metadata) -> toEntry(row))
                .all();
    }

    @Override
    public Flux<CatalogEntry> findAllByEnabled(boolean enabled) {
        return databaseClient.sql(SELECT + " WHERE enabled = :enabled ORDER BY credential_configuration_id")
                .bind(ENABLED, enabled)
                .map((row, metadata) -> toEntry(row))
                .all();
    }

    @Override
    public Mono<CatalogEntry> findById(String credentialConfigurationId) {
        return databaseClient.sql(SELECT + " WHERE credential_configuration_id = :id")
                .bind("id", credentialConfigurationId)
                .map((row, metadata) -> toEntry(row))
                .one();
    }

    @Override
    public Mono<CatalogEntry> insert(CatalogEntry entry) {
        DatabaseClient.GenericExecuteSpec spec = databaseClient.sql("""
                INSERT INTO tenant_credential_profile (
                    credential_configuration_id, schema_uri, enabled, delivery_modes,
                    validity_default_days, validity_requester_dates, validity_max_days,
                    subject_fields, subject_separator, search_identifiers)
                VALUES (
                    :id, :schemaUri, :enabled, :deliveryModes,
                    :validityDefaultDays, :validityRequesterDates, :validityMaxDays,
                    CAST(:subjectFields AS jsonb), :subjectSeparator, CAST(:searchIdentifiers AS jsonb))
                RETURNING\s""" + COLUMNS)
                .bind("id", entry.credentialConfigurationId());
        return bindConfiguration(spec, entry)
                .map((row, metadata) -> toEntry(row))
                .one()
                .onErrorMap(DuplicateKeyException.class,
                        e -> new CatalogEntryAlreadyExistsException(entry.credentialConfigurationId(), e));
    }

    @Override
    public Mono<Optional<CatalogEntry>> updateIfVersion(CatalogEntry entry, long expectedVersion) {
        DatabaseClient.GenericExecuteSpec spec = databaseClient.sql("""
                UPDATE tenant_credential_profile
                   SET schema_uri               = COALESCE(schema_uri, :schemaUri),
                       enabled                  = :enabled,
                       delivery_modes           = :deliveryModes,
                       validity_default_days    = :validityDefaultDays,
                       validity_requester_dates = :validityRequesterDates,
                       validity_max_days        = :validityMaxDays,
                       subject_fields           = CAST(:subjectFields AS jsonb),
                       subject_separator        = :subjectSeparator,
                       search_identifiers       = CAST(:searchIdentifiers AS jsonb),
                       version                  = version + 1,
                       updated_at               = now()
                 WHERE credential_configuration_id = :id AND version = :expectedVersion
                RETURNING\s""" + COLUMNS)
                .bind("id", entry.credentialConfigurationId())
                .bind("expectedVersion", expectedVersion);
        return bindConfiguration(spec, entry)
                .map((row, metadata) -> toEntry(row))
                .one()
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty());
    }

    private DatabaseClient.GenericExecuteSpec bindConfiguration(DatabaseClient.GenericExecuteSpec spec, CatalogEntry entry) {
        CatalogEntry.Validity validity = entry.validity();
        CatalogEntry.Subject subject = entry.subject();
        spec = bindNullable(spec, "schemaUri", entry.schemaUri(), String.class)
                .bind(ENABLED, entry.enabled());
        spec = bindNullable(spec, "deliveryModes", toCsv(entry.deliveryModes()), String.class);
        spec = bindNullable(spec, "validityDefaultDays", validity == null ? null : validity.defaultDays(), Integer.class)
                .bind("validityRequesterDates", validity != null && validity.requesterCanSetDates());
        spec = bindNullable(spec, "validityMaxDays", validity == null ? null : validity.maxDays(), Integer.class);
        spec = bindNullable(spec, "subjectFields", subject == null ? null : subjectFieldsJson(subject), String.class);
        spec = bindNullable(spec, "subjectSeparator", subject == null ? null : subject.separator(), String.class);
        return spec.bind("searchIdentifiers", searchIdentifiersJson(entry.searchIdentifiers()));
    }

    private static DatabaseClient.GenericExecuteSpec bindNullable(
            DatabaseClient.GenericExecuteSpec spec, String name, Object value, Class<?> type) {
        return value == null ? spec.bindNull(name, type) : spec.bind(name, value);
    }

    private static String toCsv(Set<DeliveryMode> modes) {
        if (modes == null) {
            return null;
        }
        return modes.isEmpty() ? "" : DeliveryMode.toCanonicalCsv(modes);
    }

    /** A row not configured yet has no delivery modes ({@code null}), which is not the same as none. */
    private static Set<DeliveryMode> fromCsv(String csv) {
        return csv.isEmpty() ? Set.of() : DeliveryMode.parse(csv);
    }

    private String subjectFieldsJson(CatalogEntry.Subject subject) {
        ArrayNode fields = objectMapper.createArrayNode();
        subject.fields().forEach(path -> fields.add(pathJson(path)));
        return write(fields);
    }

    private String searchIdentifiersJson(List<CatalogEntry.SearchIdentifier> identifiers) {
        ArrayNode array = objectMapper.createArrayNode();
        identifiers.forEach(identifier -> {
            ObjectNode node = array.addObject();
            node.put("name", identifier.name());
            node.set("field", pathJson(identifier.field()));
        });
        return write(array);
    }

    private ArrayNode pathJson(ClaimPath path) {
        ArrayNode node = objectMapper.createArrayNode();
        path.segments().forEach(node::add);
        return node;
    }

    private String write(JsonNode node) {
        try {
            return objectMapper.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize catalog entry JSON", e);
        }
    }

    private CatalogEntry toEntry(Row row) {
        Integer defaultDays = row.get("validity_default_days", Integer.class);
        String deliveryModes = row.get("delivery_modes", String.class);
        CatalogEntry.Validity validity = defaultDays == null ? null : new CatalogEntry.Validity(
                defaultDays,
                Boolean.TRUE.equals(row.get("validity_requester_dates", Boolean.class)),
                row.get("validity_max_days", Integer.class));
        return new CatalogEntry(
                row.get("credential_configuration_id", String.class),
                row.get("schema_uri", String.class),
                Boolean.TRUE.equals(row.get(ENABLED, Boolean.class)),
                deliveryModes == null ? null : fromCsv(deliveryModes),
                validity,
                toSubject(row.get("subject_fields", String.class), row.get("subject_separator", String.class)),
                toSearchIdentifiers(row.get("search_identifiers", String.class)),
                row.get("version", Long.class),
                row.get("created_at", Instant.class),
                row.get("updated_at", Instant.class));
    }

    private CatalogEntry.Subject toSubject(String fieldsJson, String separator) {
        if (fieldsJson == null) {
            return null;
        }
        List<ClaimPath> fields = new ArrayList<>();
        read(fieldsJson).forEach(path -> fields.add(toPath(path)));
        return new CatalogEntry.Subject(fields, separator != null ? separator : DEFAULT_SEPARATOR);
    }

    private List<CatalogEntry.SearchIdentifier> toSearchIdentifiers(String json) {
        List<CatalogEntry.SearchIdentifier> identifiers = new ArrayList<>();
        if (json != null) {
            read(json).forEach(node -> identifiers.add(
                    new CatalogEntry.SearchIdentifier(node.get("name").asText(), toPath(node.get("field")))));
        }
        return identifiers;
    }

    private static ClaimPath toPath(JsonNode node) {
        List<String> segments = new ArrayList<>();
        node.forEach(segment -> segments.add(segment.asText()));
        return new ClaimPath(segments);
    }

    private JsonNode read(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not parse catalog entry JSON stored in the database", e);
        }
    }
}
