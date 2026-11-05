package es.in2.issuer.backend.shared.infrastructure.config.logging;

import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.time.Duration;

import static es.in2.issuer.backend.shared.infrastructure.config.logging.MaskingPatternLayout.REPLACEMENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.junit.jupiter.api.Assertions.assertTimeout;

class MaskingPatternLayoutTest {

    private static final String JWT_SAMPLE =
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static final String BEARER_TOKEN = "Bearer " + JWT_SAMPLE;

    private MaskingPatternLayout layout;

    @BeforeEach
    void setUp() {
        LoggerContext context = new LoggerContext();
        layout = new MaskingPatternLayout();
        layout.setContext(context);
        layout.setPattern("%msg");
        layout.start();
    }

    @AfterEach
    void tearDown() {
        layout.stop();
    }

    // ─── mask() – Edge Cases ─────────────────────────────────────────────────

    @Test
    void mask_NullInput_ReturnsNull() {
        // Arrange
        String input = null;

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isNull();
    }

    @Test
    void mask_EmptyString_ReturnsEmptyString() {
        // Arrange
        String input = "";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isEmpty();
    }

    @Test
    void mask_BlankString_ReturnsBlankString() {
        // Arrange
        String input = "   ";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isBlank();
    }

    @Test
    void mask_PlainTextWithNoSensitiveData_ReturnsUnchanged() {
        // Arrange
        String input = "Application started successfully on port 8080";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isEqualTo(input);
    }

    // ─── mask() – Email ───────────────────────────────────────────────────────

    @Test
    void mask_StandaloneEmail_MasksEmail() {
        // Arrange
        String input = "admin@example.com";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isEqualTo(REPLACEMENT);
    }

    @Test
    void mask_EmailEmbeddedInSentence_MasksOnlyEmail() {
        // Arrange
        String input = "User admin@empresa.com authenticated successfully";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .isEqualTo("User " + REPLACEMENT + " authenticated successfully")
                .doesNotContain("admin@empresa.com");
    }

    @Test
    void mask_EmailWithSubdomainAndPlusSuffix_MasksEmail() {
        // Arrange
        String input = "Sending email to john.doe+filter@mail.company.org";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("john.doe+filter@mail.company.org");
    }

    // ─── mask() – JWT ─────────────────────────────────────────────────────────

    @Test
    void mask_StandaloneJwt_MasksJwt() {
        // Arrange – JWT_SAMPLE is a three-part eyJ… token

        // Act
        String result = MaskingPatternLayout.mask(JWT_SAMPLE);

        // Assert
        assertThat(result).isEqualTo(REPLACEMENT);
    }

    @Test
    void mask_JwtEmbeddedInLogMessage_MasksJwt() {
        // Arrange
        String input = "Validating token: " + JWT_SAMPLE + " for user 42";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .isEqualTo("Validating token: " + REPLACEMENT + " for user 42")
                .doesNotContain("eyJhbGciOiJSUzI1NiJ9");
    }

    // ─── mask() – Bearer Token ────────────────────────────────────────────────

    @Test
    void mask_BearerTokenHeader_PreservesBearerKeywordAndMasksValue() {
        // Arrange
        String input = "Authorization: " + BEARER_TOKEN;

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains("Bearer " + REPLACEMENT)
                .doesNotContain(JWT_SAMPLE);
    }

    @Test
    void mask_BearerTokenLowerCase_MasksValue() {
        // Arrange
        String input = "header: bearer someOpaqueToken123";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .containsIgnoringCase("bearer " + REPLACEMENT)
                .doesNotContain("someOpaqueToken123");
    }

    // ─── mask() – Key=Value sensitive fields ─────────────────────────────────

    @Test
    void mask_TxCodeAsJsonField_MasksTxCodeValue() {
        // Arrange
        String input = "{\"tx_code\":\"ABC123\"}";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("ABC123");
    }

    @Test
    void mask_AccessTokenAsJsonField_MasksAccessTokenValue() {
        // Arrange
        String input = "{\"access_token\":\"someAccessTokenValue\"}";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("someAccessTokenValue");
    }

    @Test
    void mask_RefreshTokenAsJsonField_MasksRefreshTokenValue() {
        // Arrange
        String input = "{\"refresh_token\":\"someRefreshTokenValue\"}";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("someRefreshTokenValue");
    }

    @Test
    void mask_PasswordAsJsonField_MasksPasswordValue() {
        // Arrange
        String input = "{\"password\":\"SuperSecret123!\"}";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("SuperSecret123!");
    }

    @Test
    void mask_SecretAsJsonField_MasksSecretValue() {
        // Arrange
        String input = "{\"secret\":\"myAppSecret\"}";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("myAppSecret");
    }

    @Test
    void mask_ClientSecretAsJsonField_MasksClientSecretValue() {
        // Arrange
        String input = "{\"client_secret\":\"oauth2ClientSecret\"}";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("oauth2ClientSecret");
    }

    @Test
    void mask_PasswordAsQueryParam_MasksPasswordValue() {
        // Arrange
        String input = "POST /token password=p@ssw0rd&grant_type=password";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("p@ssw0rd");
    }

    @Test
    void mask_SensitiveFieldWithSpacesAroundEquals_MasksValue() {
        // Arrange
        String input = "secret = mySecretValue loggedBySystem";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("mySecretValue");
    }

    // ─── mask() – Realistic log scenarios ────────────────────────────────────

    @Test
    void mask_FullRealisticLogWithEmailAndBearerToken_MasksAllSensitiveData() {
        // Arrange
        String input = "User admin@empresa.com authenticated with token " + BEARER_TOKEN;

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains("User " + REPLACEMENT)
                .contains("Bearer " + REPLACEMENT)
                .doesNotContain("admin@empresa.com")
                .doesNotContain(JWT_SAMPLE);
    }

    @Test
    void mask_JsonLogWithMultipleSensitiveFields_MasksAllFields() {
        // Arrange
        String input = "{\"user\":\"" + "alice@test.com" + "\","
                + "\"access_token\":\"tokenValue\","
                + "\"refresh_token\":\"refreshValue\","
                + "\"password\":\"secret123\"}";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .doesNotContain("alice@test.com")
                .doesNotContain("tokenValue")
                .doesNotContain("refreshValue")
                .doesNotContain("secret123");
        assertThat(result.chars().filter(c -> c == '*').count()).isGreaterThan(0L);
    }

    @Test
    void mask_TokenExchangeRequestLog_MasksTokensAndKeepsGrantType() {
        // Arrange
        String input = "Token exchange: grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                + " access_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig"
                + " refresh_token=rT_abc123";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result)
                .contains("grant_type=urn:ietf:params:oauth:grant-type:token-exchange")
                .doesNotContain("eyJhbGciOiJSUzI1NiJ9")
                .doesNotContain("rT_abc123");
    }

    // ─── mask() – False Positive Prevention ──────────────────────────────────

    @Test
    void mask_StandardUuid_NotMasked() {
        // Arrange
        String input = "Processing request with correlationId=550e8400-e29b-41d4-a716-446655440000";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isEqualTo(input);
    }

    @Test
    void mask_UrlWithoutEmail_NotMasked() {
        // Arrange
        String input = "Calling external service at https://api.example.com/v1/resources";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isEqualTo(input);
    }

    @Test
    void mask_WordGrantTypeContainingTokenSubstring_NotMasked() {
        // Arrange
        String input = "grant_type=authorization_code&redirect_uri=https://app.example.com/cb";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isEqualTo(input);
    }

    @Test
    void mask_NormalWordPasswordless_NotMasked() {
        // Arrange
        String input = "Authentication strategy: passwordless via OTP";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isEqualTo(input);
    }

    @Test
    void mask_JsonKeyNamedAccessTokenType_KeyNameNotMasked() {
        // Arrange
        String input = "{\"token_type\":\"Bearer\",\"expires_in\":3600}";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isEqualTo(input);
    }

    @Test
    void mask_LogLevelAndThreadName_NotMasked() {
        // Arrange
        String input = "2025-01-01 12:00:00 INFO  [main] c.example.Service - Request processed in 45ms";

        // Act
        String result = MaskingPatternLayout.mask(input);

        // Assert
        assertThat(result).isEqualTo(input);
    }

    // ─── doLayout() ───────────────────────────────────────────────────────────

    @Test
    void doLayout_MessageWithEmail_MasksEmail() {
        // Arrange
        ILoggingEvent event = mock(ILoggingEvent.class);
        when(event.getFormattedMessage()).thenReturn("Contact support@company.com for issues");

        // Act
        String result = layout.doLayout(event);

        // Assert
        assertThat(result)
                .contains(REPLACEMENT)
                .doesNotContain("support@company.com");
    }

    @Test
    void doLayout_MessageWithBearerToken_MasksBearerValue() {
        // Arrange
        ILoggingEvent event = mock(ILoggingEvent.class);
        when(event.getFormattedMessage()).thenReturn("Received Authorization: Bearer mySecretBearerToken");

        // Act
        String result = layout.doLayout(event);

        // Assert
        assertThat(result)
                .contains("Bearer " + REPLACEMENT)
                .doesNotContain("mySecretBearerToken");
    }

    @Test
    void doLayout_MessageWithNoSensitiveData_ReturnsFormattedMessageUnchanged() {
        // Arrange
        String plainMessage = "Scheduler triggered at fixed rate";
        ILoggingEvent event = mock(ILoggingEvent.class);
        when(event.getFormattedMessage()).thenReturn(plainMessage);

        // Act
        String result = layout.doLayout(event);

        // Assert
        assertThat(result).isEqualTo(plainMessage);
    }

    // ─── Regression: false-positive fixes ────────────────────────────────────

    @Test
    void mask_PaddedJwtWithEqualsSign_MasksJwt() {
        // Arrange – base64url segments that include '=' padding characters
        String paddedJwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0=.SflKxwRJSMeKKF2QT4fw==";

        // Act
        String result = MaskingPatternLayout.mask(paddedJwt);

        // Assert
        assertThat(result)
                .isEqualTo(REPLACEMENT)
                .doesNotContain("eyJhbGciOiJSUzI1NiJ9");
    }

    @Test
    void mask_EyJPrefixWithoutValidTwoSeparators_NotMasked() {
        // Arrange – 'eyJ' with only one dot segment should NOT be treated as a JWT
        String notAJwt = "eyJ.onlyone";

        // Act
        String result = MaskingPatternLayout.mask(notAJwt);

        // Assert
        assertThat(result).isEqualTo(notAJwt);
    }

    @Test
    void mask_AuthorizationCodeInQueryString_MasksCodeKeepingOtherParams() {
        String result = MaskingPatternLayout.mask(
                "grant_type=authorization_code&code=AUTH-CODE-123&redirect_uri=https://app.example.com/cb");

        assertThat(result)
                .isEqualTo("grant_type=authorization_code&code=" + REPLACEMENT + "&redirect_uri=https://app.example.com/cb");
    }

    @Test
    void mask_CodeAsJsonField_MasksCode() {
        assertThat(MaskingPatternLayout.mask("{\"code\":\"482913\"}")).doesNotContain("482913");
    }

    @Test
    void mask_OtpAsKeyValue_MasksOtp() {
        assertThat(MaskingPatternLayout.mask("Verifying otp=482913 for tenant sandbox"))
                .isEqualTo("Verifying otp=" + REPLACEMENT + " for tenant sandbox");
    }

    @Test
    void mask_CamelCaseRefreshToken_MasksToken() {
        assertThat(MaskingPatternLayout.mask("{\"refreshToken\":\"rT_abc123\"}")).doesNotContain("rT_abc123");
    }

    @Test
    void mask_Uuid_IsLeftUnchanged() {
        String input = "Processing procedure 550e8400-e29b-41d4-a716-446655440000";

        assertThat(MaskingPatternLayout.mask(input)).isEqualTo(input);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "error_code=expired_code",
            "Failed to send a verification code: org.springframework.mail.MailSendException",
            "Failed to resolve name. status=Status{code=UNAVAILABLE, description=Unable to resolve host}",
            "{\"code\":\"invalid_request\"}",
            "eyJ.onlyone"
    })
    void mask_LooksSensitiveButIsNot_ReturnsUnchanged(String input) {
        assertThat(MaskingPatternLayout.mask(input)).isEqualTo(input);
    }

    @Test
    void mask_UrlEncodedEmailInQueryString_MasksEmail() {
        String input = "Securing GET /error?client_id=mask.test%40example.com"
                + "&login_hint=john.doe%2Bfilter%40mail.company.org&response_type=code";

        assertThat(MaskingPatternLayout.mask(input))
                .isEqualTo("Securing GET /error?client_id=" + REPLACEMENT
                        + "&login_hint=" + REPLACEMENT + "&response_type=code");
    }

    // ─── mask() – review findings ─────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "wallet_access_token=s3cr3tValue",
            "db_password=s3cr3tValue",
            "\"db_password\":\"s3cr3tValue\"",
            "keystorePassword=s3cr3tValue",
            "jwtSecret=s3cr3tValue",
            "AUDIT_QUERY_CURSOR_SECRET=s3cr3tValue",
            "pre-authorized_code=s3cr3tValue",
            "\"pre-authorized_code\":\"s3cr3tValue\"",
            "preAuthorizedCode=s3cr3tValue",
            "Offer[txCode=s3cr3tValue, length=6]",
            "pin=s3cr3tValue",
            "\"tx_pin\":\"s3cr3tValue\"",
            "vp_token=s3cr3tValue",
            "\"vp_token\":\"s3cr3tValue\"",
            "Authorization: Basic s3cr3tValue",
            "password=\"correct horse s3cr3tValue\""
    })
    void mask_SecretUnderAnyKeyForm_MasksTheWholeValue(String input) {
        assertThat(MaskingPatternLayout.mask(input))
                .contains(MaskingPatternLayout.REPLACEMENT)
                .doesNotContain("s3cr3tValue");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "spin=keep",
            "pin_length=6",
            "totp_enabled=true",
            "token_type=Bearer",
            "error_code=expired_code",
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&scope=openid"
    })
    void mask_KeyThatIsNotASecret_ReturnsUnchanged(String input) {
        assertThat(MaskingPatternLayout.mask(input)).isEqualTo(input);
    }

    @Test
    void mask_SdJwtWithDisclosuresAndKeyBinding_MasksEverySegment() {
        String sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
                + "~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ"
                + "~eyJ0eXAiOiJrYitqd3QifQ.eyJub25jZSI6IngifQ.a2Jz";

        assertThat(MaskingPatternLayout.mask(sdJwt)).isEqualTo(MaskingPatternLayout.REPLACEMENT);
    }

    @Test
    void mask_SdJwtWithManyDisclosures_MasksWithoutOverflowingTheStack() {
        String sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln" + "~WyJzYWx0Il0".repeat(50_000);

        assertThat(MaskingPatternLayout.mask(sdJwt)).isEqualTo(MaskingPatternLayout.REPLACEMENT);
    }

    @Test
    void mask_JwtWithEmptySignatureSegment_MasksToken() {
        assertThat(MaskingPatternLayout.mask("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."))
                .isEqualTo(MaskingPatternLayout.REPLACEMENT);
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "eyJ", "=eyJ", "code="})
    void mask_LongRepetitionThatIsNotASecret_StaysLinear(String unit) {
        String input = unit.repeat(200_000 / unit.length());

        String result = assertTimeout(Duration.ofSeconds(15), () -> MaskingPatternLayout.mask(input));

        assertThat(result).isEqualTo(input);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "id_token_hint=%s",
            "client_assertion=%s",
            "request=%s",
            "id_token_hint%%3D%s",
            "\"assertion\":\"%s\""
    })
    void mask_JwtAfterAnAssignmentOrQuote_MasksToken(String format) {
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";

        assertThat(MaskingPatternLayout.mask(format.formatted(jwt)))
                .contains(MaskingPatternLayout.REPLACEMENT)
                .doesNotContain(jwt);
    }

    // ─── truncate() ───────────────────────────────────────────────────────────

    @Test
    void truncate_MessageWithinTheLimit_ReturnsItUnchanged() {
        String message = "a".repeat(MaskingPatternLayout.MAX_MESSAGE_LENGTH);

        assertThat(MaskingPatternLayout.truncate(message)).isEqualTo(message);
        assertThat(MaskingPatternLayout.truncate(null)).isNull();
    }

    @Test
    void truncate_LongMessage_CutsAtASeparatorAndMarksIt() {
        String result = MaskingPatternLayout.truncate("word ".repeat(5_000));

        assertThat(result).endsWith(" " + MaskingPatternLayout.TRUNCATED);
        assertThat(result.length())
                .isLessThanOrEqualTo(MaskingPatternLayout.MAX_MESSAGE_LENGTH + MaskingPatternLayout.TRUNCATED.length());
    }

    @Test
    void truncate_SecretAcrossTheLimit_DropsItWhole() {
        String padding = "a ".repeat((MaskingPatternLayout.MAX_MESSAGE_LENGTH - 50) / 2);
        String jwt = "eyJhbGciOiJFUzI1NiJ9." + "x".repeat(100) + ".c2ln";

        String result = MaskingPatternLayout.truncate(padding + jwt);

        assertThat(result).isEqualTo(padding + MaskingPatternLayout.TRUNCATED);
    }

    @Test
    void truncate_LongMessageWithoutSeparators_KeepsOnlyTheMark() {
        assertThat(MaskingPatternLayout.truncate("a".repeat(20_000))).isEqualTo(MaskingPatternLayout.TRUNCATED);
    }

    @Test
    void doLayout_LongMessageWithException_TruncatesTheMessageAndKeepsTheStackTrace() {
        LoggerContext context = new LoggerContext();
        MaskingPatternLayout patternLayout = new MaskingPatternLayout();
        patternLayout.setContext(context);
        patternLayout.setPattern("%m%n%ex");
        patternLayout.start();
        LoggingEvent event = new LoggingEvent(MaskingPatternLayoutTest.class.getName(), context.getLogger("test-logger"),
                Level.ERROR, "word ".repeat(5_000), new IllegalStateException("failure"), null);

        String line = patternLayout.doLayout(event);

        assertThat(line).contains(MaskingPatternLayout.TRUNCATED, "java.lang.IllegalStateException: failure", "\tat ");
    }
}
