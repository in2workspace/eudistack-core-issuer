package es.in2.issuer.backend.shared.domain.service;

import java.time.Instant;

public interface RefreshTokenService {
    String issueRefreshToken();
    long computeRefreshTokenExpirationTime(Instant issueTime);
}
