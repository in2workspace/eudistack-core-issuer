package es.in2.issuer.backend.signing.domain.model.dto;

import java.time.Instant;

public record CacheEntry(String value, Instant expiresAt) {}