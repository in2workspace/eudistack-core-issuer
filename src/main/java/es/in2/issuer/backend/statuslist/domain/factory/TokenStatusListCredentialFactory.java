package es.in2.issuer.backend.statuslist.domain.factory;

import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.TOKEN_STATUS_LIST_ENTRY_TYPE;
import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

/**
 * Builds payloads for draft-ietf-oauth-status-list (Token Status List).
 *
 * JWT payload structure:
 * {
 *   "sub": "https://issuer.example.com/token/v1/credentials/status/42",
 *   "iss": "did:elsi:...",
 *   "iat": 1234567890,
 *   "exp": 1234654290,
 *   "status_list": {
 *     "bits": 1,
 *     "lst": "<base64url-gzip-compressed-bitstring>"
 *   }
 * }
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class TokenStatusListCredentialFactory {

    private static final int BITS_PER_STATUS = 1;
    private static final long DEFAULT_LIFETIME_DAYS = 365;

    public Map<String, Object> buildUnsigned(String listUrl, String issuerId, String purpose, String encodedList) {
        requireNonNullParam(listUrl, "listUrl");
        requireNonNullParam(issuerId, "issuerId");
        requireNonNullParam(purpose, "purpose");
        requireNonNullParam(encodedList, "encodedList");

        // Strip multibase 'u' prefix — TokenStatusList uses raw base64url
        String rawBase64url = encodedList;
        if (rawBase64url.charAt(0) == 'u') {
            rawBase64url = rawBase64url.substring(1);
        }

        Instant now = Instant.now();
        Instant exp = now.plus(DEFAULT_LIFETIME_DAYS, ChronoUnit.DAYS);

        Map<String, Object> statusList = new LinkedHashMap<>();
        statusList.put("bits", BITS_PER_STATUS);
        statusList.put("lst", rawBase64url);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", listUrl);
        payload.put("iss", issuerId);
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", exp.getEpochSecond());
        payload.put("status_list", statusList);

        return payload;
    }

    public StatusListEntry buildStatusListEntry(String listUrl, Integer idx, StatusPurpose purpose) {
        log.debug("Building token status list entry - idx: {}", idx);
        requireNonNullParam(listUrl, "listUrl");
        requireNonNullParam(idx, "idx");
        requireNonNullParam(purpose, "purpose");

        String id = listUrl + "#" + idx;

        return StatusListEntry.builder()
                .id(id)
                .type(TOKEN_STATUS_LIST_ENTRY_TYPE)
                .statusPurpose(purpose)
                .statusListIndex(String.valueOf(idx))
                .statusListCredential(listUrl)
                .build();
    }
}
