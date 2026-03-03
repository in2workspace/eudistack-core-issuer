package es.in2.issuer.backend.oidc4vci.infrastructure.config;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class Oid4vciProfilePropertiesTest {

    @Test
    void isAuthorizationCodeEnabled_shouldReturnTrueWhenAuthCodeInGrants() {
        var props = new Oid4vciProfileProperties(
                List.of("authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                null
        );

        assertTrue(props.isAuthorizationCodeEnabled());
    }

    @Test
    void isAuthorizationCodeEnabled_shouldReturnFalseWhenNotInGrants() {
        var props = new Oid4vciProfileProperties(
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                null
        );

        assertFalse(props.isAuthorizationCodeEnabled());
    }

    @Test
    void isPreAuthorizedCodeEnabled_shouldReturnTrueWhenPreAuthInGrants() {
        var props = new Oid4vciProfileProperties(
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                null
        );

        assertTrue(props.isPreAuthorizedCodeEnabled());
    }

    @Test
    void isHaipProfile_shouldReturnTrueForFullHaip() {
        var authCode = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, true, List.of("S256"),
                true, List.of("ES256"),
                "attest_jwt_client_auth", true
        );
        var props = new Oid4vciProfileProperties(
                List.of("authorization_code"),
                authCode
        );

        assertTrue(props.isHaipProfile());
    }

    @Test
    void isHaipProfile_shouldReturnFalseWhenParNotRequired() {
        var authCode = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                false, true, List.of("S256"),
                true, List.of("ES256"),
                "attest_jwt_client_auth", true
        );
        var props = new Oid4vciProfileProperties(
                List.of("authorization_code"),
                authCode
        );

        assertFalse(props.isHaipProfile());
    }

    @Test
    void isHaipProfile_shouldReturnFalseWhenClientAuthIsNone() {
        var authCode = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, true, List.of("S256"),
                true, List.of("ES256"),
                "none", true
        );
        var props = new Oid4vciProfileProperties(
                List.of("authorization_code"),
                authCode
        );

        assertFalse(props.isHaipProfile());
    }

    @Test
    void defaults_shouldBeAppliedWhenNullsProvided() {
        var props = new Oid4vciProfileProperties(null, null);

        assertNotNull(props.grantsSupported());
        assertTrue(props.isPreAuthorizedCodeEnabled());
        assertFalse(props.isAuthorizationCodeEnabled());
        assertNotNull(props.authorizationCode());
        assertFalse(props.authorizationCode().requirePar());
        assertFalse(props.authorizationCode().requireDpop());
        assertEquals("none", props.authorizationCode().clientAuthMethod());
    }

    @Test
    void authorizationCodeProperties_shouldApplyDefaults() {
        var authCode = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, true, null, true, null, null, false
        );

        assertEquals(List.of("S256"), authCode.pkceMethods());
        assertEquals(List.of("ES256"), authCode.dpopSigningAlgs());
        assertEquals("none", authCode.clientAuthMethod());
    }
}
