package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException.Violation;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.model.query.PageCursor;
import es.in2.issuer.backend.shared.domain.model.query.SearchIdentifierCriterion;
import es.in2.issuer.backend.shared.domain.util.SubjectSearch;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceListParameters.CREDENTIAL_CONFIGURATION_ID;
import static es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceListParameters.CREDENTIAL_CONFIGURATION_ID_MAX_LENGTH;
import static es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceListParameters.CURSOR;
import static es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceListParameters.LIFE_CYCLE_STATUS;
import static es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceListParameters.LIMIT;
import static es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceListParameters.TENANT;
import static es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceListParameters.TENANT_MAX_LENGTH;

/**
 * The body of {@code POST /api/v1/issuances/search} (EUD-255 contract, {@code SearchRequest}), checked for shape
 * before the permission (API-10). The body carries personal data -- the name or the identifier searched -- so it is
 * parsed here from its text: a body that is not JSON is reported without the parser's message, which quotes it, and
 * no violation repeats a value. Every field with a problem gets its violation.
 */
final class IssuanceSearchParameters {

    static final String BODY = "body";
    static final String IDENTIFIER_TYPE = "identifier_type";
    static final String IDENTIFIER = "identifier";
    static final String SUBJECT = "subject";

    static final int IDENTIFIER_TYPE_MAX_LENGTH = 50;
    static final int IDENTIFIER_MAX_LENGTH = 100;
    static final int SUBJECT_MIN_CHARACTERS = 3;
    static final int SUBJECT_MAX_LENGTH = 100;

    private static final Set<String> FIELDS = Set.of(IDENTIFIER_TYPE, IDENTIFIER, SUBJECT, LIFE_CYCLE_STATUS,
            CREDENTIAL_CONFIGURATION_ID, TENANT, LIMIT, CURSOR);
    /** A field name the client sent is named back only when it looks like one; anything else is the body's. */
    private static final Pattern FIELD_NAME = Pattern.compile("[A-Za-z0-9_]{1,50}");
    private static final Pattern WHITESPACE = Pattern.compile("\\s");
    private static final ObjectMapper JSON = JsonMapper.builder()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .build();

    private IssuanceSearchParameters() {
    }

    /**
     * The body as it came, in bytes: Spring's text decoder logs what it decodes, so the body never goes through it
     * (AD-5). Bytes that are not UTF-8 are not a JSON object.
     */
    static IssuanceQuery toQuery(byte[] body) {
        if (body == null) {
            return toQuery((String) null);
        }
        try {
            return toQuery(StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(body))
                    .toString());
        } catch (CharacterCodingException notUtf8) {
            throw InvalidQueryException.of(BODY, "must be a JSON object");
        }
    }

    static IssuanceQuery toQuery(String body) {
        JsonNode search = parse(body);
        List<Violation> violations = new ArrayList<>();
        Iterator<String> names = search.fieldNames();
        while (names.hasNext()) {
            String name = names.next();
            if (!FIELDS.contains(name)) {
                violations.add(new Violation(FIELD_NAME.matcher(name).matches() ? name : BODY,
                        "is not a field of the search"));
            }
        }
        String identifierType = text(search, IDENTIFIER_TYPE, IDENTIFIER_TYPE_MAX_LENGTH, violations);
        String identifier = text(search, IDENTIFIER, IDENTIFIER_MAX_LENGTH, violations);
        String subject = subject(search, violations);
        criterion(search, violations);
        Set<CredentialStatusEnum> statuses = statuses(search.get(LIFE_CYCLE_STATUS), violations);
        String entry = text(search, CREDENTIAL_CONFIGURATION_ID, CREDENTIAL_CONFIGURATION_ID_MAX_LENGTH, violations);
        String tenant = text(search, TENANT, TENANT_MAX_LENGTH, violations);
        int limit = limit(search.get(LIMIT), violations);
        PageCursor cursor = cursor(search.get(CURSOR), violations);
        if (!violations.isEmpty()) {
            throw new InvalidQueryException(violations);
        }
        SearchIdentifierCriterion searchedIdentifier = identifierType == null
                ? null
                : SearchIdentifierCriterion.searched(identifierType, identifier);
        return new IssuanceQuery(statuses, entry, tenant, limit, cursor, subject, searchedIdentifier);
    }

    private static JsonNode parse(String body) {
        if (body == null || body.isBlank()) {
            throw InvalidQueryException.of(BODY, "must be a JSON object");
        }
        try {
            JsonNode search = JSON.readTree(body);
            if (search == null || !search.isObject()) {
                throw InvalidQueryException.of(BODY, "must be a JSON object");
            }
            return search;
        } catch (JsonProcessingException notJson) {
            // The parser's message quotes the body: it is neither kept nor logged.
            throw InvalidQueryException.of(BODY, "must be a JSON object");
        }
    }

    /** One criterion: {@code identifier_type} and {@code identifier}, or {@code subject}, never both nor neither. */
    private static void criterion(JsonNode search, List<Violation> violations) {
        boolean hasType = search.has(IDENTIFIER_TYPE);
        boolean hasIdentifier = search.has(IDENTIFIER);
        boolean hasSubject = search.has(SUBJECT);
        if (hasSubject && (hasType || hasIdentifier)) {
            violations.add(new Violation(SUBJECT, "cannot go with identifier_type or identifier"));
        } else if (!hasSubject && !hasType && !hasIdentifier) {
            violations.add(new Violation(SUBJECT, "or identifier_type and identifier is required"));
        } else if (hasType != hasIdentifier) {
            violations.add(hasType
                    ? new Violation(IDENTIFIER, "is required with identifier_type")
                    : new Violation(IDENTIFIER_TYPE, "is required with identifier"));
        }
    }

    private static String subject(JsonNode search, List<Violation> violations) {
        String subject = text(search, SUBJECT, SUBJECT_MAX_LENGTH, violations);
        if (subject == null || subject.isBlank()) {
            return subject;
        }
        // AD-9: counted on the text compared, so marks alone (accents without a letter) count for nothing.
        String withoutSpaces = WHITESPACE.matcher(SubjectSearch.normalize(subject)).replaceAll("");
        if (withoutSpaces.codePointCount(0, withoutSpaces.length()) < SUBJECT_MIN_CHARACTERS) {
            violations.add(new Violation(SUBJECT, "must have at least " + SUBJECT_MIN_CHARACTERS
                    + " characters not counting spaces"));
        }
        return subject;
    }

    /** A text field: a JSON string, not blank, of at most {@code maxLength} characters; null when absent. */
    private static String text(JsonNode search, String field, int maxLength, List<Violation> violations) {
        JsonNode value = search.get(field);
        if (value == null) {
            return null;
        }
        if (!value.isTextual()) {
            violations.add(new Violation(field, "must be a string"));
            return null;
        }
        return IssuanceListParameters.text(value.textValue(), field, maxLength, violations);
    }

    private static Set<CredentialStatusEnum> statuses(JsonNode value, List<Violation> violations) {
        if (value == null) {
            return Set.of();
        }
        Violation invalid = new Violation(LIFE_CYCLE_STATUS, "must be a list of one or more of "
                + EnumSet.allOf(CredentialStatusEnum.class));
        if (!value.isArray() || value.isEmpty()) {
            violations.add(invalid);
            return Set.of();
        }
        Set<CredentialStatusEnum> statuses = EnumSet.noneOf(CredentialStatusEnum.class);
        for (JsonNode item : value) {
            Optional<CredentialStatusEnum> status = item.isTextual()
                    ? IssuanceListParameters.status(item.textValue())
                    : Optional.empty();
            if (status.isEmpty()) {
                violations.add(invalid);
                return Set.of();
            }
            statuses.add(status.get());
        }
        return statuses;
    }

    private static int limit(JsonNode value, List<Violation> violations) {
        if (value == null) {
            return IssuanceQuery.DEFAULT_LIMIT;
        }
        if (value.isIntegralNumber() && value.canConvertToInt()
                && value.intValue() >= 1 && value.intValue() <= IssuanceQuery.MAX_LIMIT) {
            return value.intValue();
        }
        violations.add(new Violation(LIMIT, "must be an integer from 1 to " + IssuanceQuery.MAX_LIMIT));
        return IssuanceQuery.DEFAULT_LIMIT;
    }

    private static PageCursor cursor(JsonNode value, List<Violation> violations) {
        if (value == null) {
            return null;
        }
        if (!value.isTextual()) {
            violations.add(new Violation(CURSOR, "is not a cursor of this API"));
            return null;
        }
        return IssuanceListParameters.cursor(value.textValue(), violations);
    }
}
