package es.in2.issuer.backend.shared.domain.service.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Base64;

import static es.in2.issuer.backend.shared.domain.util.Constants.REFRESH_TOKEN_EXPIRATION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceImplTest {

    @InjectMocks
    private RefreshTokenServiceImpl refreshTokenService;

    private Instant testIssueTime;

    @BeforeEach
    void setUp() {
        testIssueTime = Instant.parse("2024-01-15T10:30:45Z");
    }

    @Test
    void issueRefreshToken_ShouldReturnUniqueTokensOnMultipleCalls() {
        String firstToken = refreshTokenService.issueRefreshToken();
        String secondToken = refreshTokenService.issueRefreshToken();

        assertThat(firstToken).isNotEqualTo(secondToken);
    }

    @Test
    void issueRefreshToken_ShouldReturnBase64EncodedToken() {
        String refreshToken = refreshTokenService.issueRefreshToken();
        assertThatCode(() ->
                Base64.getUrlDecoder().decode(refreshToken)
        ).doesNotThrowAnyException();

    }

    @Test
    void issueRefreshToken_ShouldReturnTokenWithMinimumLength() {
        String refreshToken = refreshTokenService.issueRefreshToken();

        assertThat(refreshToken.length()).isGreaterThanOrEqualTo(40);
    }

    @Test
    void computeRefreshTokenExpirationTime_ShouldReturnCorrectExpirationTime() {
        long actualExpirationTime = refreshTokenService.computeRefreshTokenExpirationTime(testIssueTime);

        assertThat(actualExpirationTime).isEqualTo(testIssueTime.plusSeconds(REFRESH_TOKEN_EXPIRATION * 3600).getEpochSecond());
    }
}
