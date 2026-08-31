package es.in2.issuer.backend.statuslist.domain.factory;

import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.util.BitstringEncoder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.Deflater;

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
 *     "lst": "<base64url(zlib-deflate(bitstring))>"
 *   }
 * }
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class TokenStatusListCredentialFactory {

    private static final int BITS_PER_STATUS = 1;
    private static final long DEFAULT_LIFETIME_DAYS = 365;

    private final BitstringEncoder bitstringEncoder = new BitstringEncoder();

    public Map<String, Object> buildUnsigned(String listUrl, String issuerId, String purpose, String encodedList) {
        requireNonNullParam(listUrl, "listUrl");
        requireNonNullParam(issuerId, "issuerId");
        requireNonNullParam(purpose, "purpose");
        requireNonNullParam(encodedList, "encodedList");

        // encodedList is the shared bitstring storage format (multibase 'u' + base64url + GZIP,
        // BitstringEncoder), reused as-is for the W3C Bitstring Status List JWT. But
        // draft-ietf-oauth-status-list §4.1 mandates "DEFLATE [RFC1951] with the ZLIB
        // [RFC1950] data format" for the `lst` claim - i.e. raw DEFLATE wrapped in the 2-byte
        // zlib header + Adler-32 trailer, which is neither GZIP (RFC 1952) nor bare RFC 1951.
        // Passing the GZIP bytes through produced an `lst` no conformant reader could inflate;
        // so did emitting header-less DEFLATE (java.util.zip.Inflater with the default
        // constructor, as every conformant reader uses: "incorrect header check").
        // Decode back to the raw bitstring and re-compress with zlib-framed DEFLATE.
        byte[] rawBits = bitstringEncoder.decodeToRawBytes(encodedList);
        String rawBase64url = Base64.getUrlEncoder().withoutPadding().encodeToString(deflateZlib(rawBits));

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

    /** DEFLATE (RFC 1951) in the ZLIB (RFC 1950) data format, as draft-ietf-oauth-status-list §4.1 requires. */
    private byte[] deflateZlib(byte[] input) {
        // java:S2095 kept firing on a manual try/finally around Deflater.end(): SonarJava's
        // dataflow only accepts try-with-resources here. Java 25 made Deflater AutoCloseable
        // with close() calling end() (@since 25), so the JDK type goes straight into the
        // resource list - no wrapper needed, and the compiler guarantees close() runs.
        // nowrap=false (the single-arg constructor): keep the zlib header/trailer the spec mandates.
        try (Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION)) {
            deflater.setInput(input);
            deflater.finish();

            ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length);
            byte[] buffer = new byte[8 * 1024];
            while (!deflater.finished()) {
                int written = deflater.deflate(buffer);
                baos.write(buffer, 0, written);
            }
            return baos.toByteArray();
        }
    }
}
