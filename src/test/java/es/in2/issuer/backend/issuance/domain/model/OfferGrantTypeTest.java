package es.in2.issuer.backend.issuance.domain.model;

import es.in2.issuer.backend.issuance.domain.exception.InvalidGrantTypeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class OfferGrantTypeTest {

    @Test
    void absentGrantIsTheAuthorizationCode() {
        assertEquals(OfferGrantType.AUTHORIZATION_CODE, OfferGrantType.fromRequest(null));
    }

    @Test
    void acceptsTheAuthorizationCode() {
        assertEquals(OfferGrantType.AUTHORIZATION_CODE, OfferGrantType.fromRequest("authorization_code"));
    }

    @Test
    void acceptsThePreAuthorizedCode() {
        assertEquals(OfferGrantType.PRE_AUTHORIZED_CODE,
                OfferGrantType.fromRequest("urn:ietf:params:oauth:grant-type:pre-authorized_code"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"client_credentials", "refresh_token", "Authorization_Code", "", " authorization_code",
            "pre-authorized_code", "authorization_code\r\nX-Injected: 1"})
    void rejectsAnyOtherValueWithoutEchoingIt(String grantType) {
        InvalidGrantTypeException ex = assertThrows(InvalidGrantTypeException.class,
                () -> OfferGrantType.fromRequest(grantType));
        assertEquals(OfferGrantType.INVALID_MESSAGE, ex.getMessage());
    }
}
