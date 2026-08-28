package es.in2.issuer.backend.signing.domain.model.dto;

import java.time.Instant;

public record CacheEntry<T>(T value, Instant expiresAt) {}
