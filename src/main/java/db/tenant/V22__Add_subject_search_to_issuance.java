package db.tenant;

import es.in2.issuer.backend.shared.domain.util.SubjectSearch;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * EUD-255 design 1.1, AD-9 and §5: the issuance process gets {@code subject_search}, its subject as the search by
 * name compares it, with a trigram index for {@code LIKE '%text%'}.
 *
 * <p>A Java migration and not SQL: the existing rows are backfilled with {@link SubjectSearch}, the same function the
 * application writes and searches with. PostgreSQL has no NFD decomposition nor a mark class to reproduce it, and
 * {@code unaccent} was ruled out by AD-9. From then on {@code IssuanceMapper} writes it on every save.
 *
 * <ul>
 *   <li>{@code pg_trgm} goes to {@code public}, as {@code uuid-ossp}: this runs with the tenant schema as default, and
 *       an extension created without a schema would land in the first tenant's. Each environment installs it before
 *       the migration (design §6), so here it usually exists already and nothing happens.</li>
 *   <li>The operator class is qualified ({@code public.gin_trgm_ops}) for the same reason.</li>
 * </ul>
 * Idempotent: the column, the backfill and the index can run again.
 */
@SuppressWarnings("java:S101") // Flyway takes the version and the description from the class name.
public class V22__Add_subject_search_to_issuance extends BaseJavaMigration {

    private static final int BATCH_SIZE = 500;

    @Override
    public void migrate(Context context) throws SQLException {
        Connection connection = context.getConnection();
        try (Statement ddl = connection.createStatement()) {
            ddl.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public");
            ddl.execute("ALTER TABLE issuance ADD COLUMN IF NOT EXISTS subject_search TEXT");
        }
        backfill(connection);
        try (Statement ddl = connection.createStatement()) {
            ddl.execute("CREATE INDEX IF NOT EXISTS idx_issuance_subject_search "
                    + "ON issuance USING gin (subject_search public.gin_trgm_ops)");
        }
    }

    /** Every process with a subject and no search form yet, a batch at a time. */
    private static void backfill(Connection connection) throws SQLException {
        Map<UUID, String> batch;
        do {
            batch = nextBatch(connection);
            try (PreparedStatement update = connection.prepareStatement(
                    "UPDATE issuance SET subject_search = ? WHERE issuance_id = ?")) {
                for (Map.Entry<UUID, String> row : batch.entrySet()) {
                    update.setString(1, SubjectSearch.normalize(row.getValue()));
                    update.setObject(2, row.getKey());
                    update.addBatch();
                }
                update.executeBatch();
            }
        } while (batch.size() == BATCH_SIZE);
    }

    private static Map<UUID, String> nextBatch(Connection connection) throws SQLException {
        Map<UUID, String> batch = new LinkedHashMap<>();
        try (PreparedStatement select = connection.prepareStatement(
                "SELECT issuance_id, subject FROM issuance WHERE subject IS NOT NULL AND subject_search IS NULL "
                        + "ORDER BY issuance_id LIMIT " + BATCH_SIZE);
             ResultSet rows = select.executeQuery()) {
            while (rows.next()) {
                batch.put(rows.getObject("issuance_id", UUID.class), rows.getString("subject"));
            }
        }
        return batch;
    }
}
