package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpMethod;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ApiOperationResolverTest {

    private static final String ID = "0b0d7b38-4bf8-4c2b-9a6f-5a3a07a3f8a1";

    @ParameterizedTest
    @CsvSource({
            "POST,  /api/v1/issuances,                                 ISSUANCE",
            "POST,  /api/v1/issuances/" + ID + "/credential-offer,     ISSUANCE",
            "POST,  /api/v1/issuances/" + ID + "/revocation,           REVOCATION",
            "PATCH, /api/v1/issuances/" + ID + ",                      REVOCATION",
            "POST,  /w3c/v1/credentials/status/revoke,                 REVOCATION",
            "POST,  /api/v1/issuances/search,                          SEARCH",
            "GET,   /api/v1/issuances,                                 READ",
            "GET,   /api/v1/issuances/" + ID + ",                      READ"
    })
    void resolve_theRoutesOfTheThreeApis(String method, String path, ApiOperation expected) {
        assertThat(ApiOperationResolver.resolve(HttpMethod.valueOf(method), path)).contains(expected);
    }

    @ParameterizedTest
    @CsvSource({
            "POST,   /oauth/token",
            "GET,    /api/v1/attestation-catalog",
            "DELETE, /api/v1/issuances/" + ID,
            "POST,   /issuer/api/v1/issuances"
    })
    void resolve_anyOtherRoute_hasNoOperation(String method, String path) {
        assertThat(ApiOperationResolver.resolve(HttpMethod.valueOf(method), path)).isEmpty();
    }

    @org.junit.jupiter.api.Test
    void resolve_withoutMethodOrPath_hasNoOperation() {
        assertThat(ApiOperationResolver.resolve(null, "/api/v1/issuances")).isEqualTo(Optional.empty());
        assertThat(ApiOperationResolver.resolve(HttpMethod.POST, null)).isEmpty();
    }
}
