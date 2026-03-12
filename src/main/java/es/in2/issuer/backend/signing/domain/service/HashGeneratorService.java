package es.in2.issuer.backend.signing.domain.service;

import es.in2.issuer.backend.signing.domain.exception.HashGenerationException;

public interface HashGeneratorService {
    String computeHash(String unsignedDocument, String algorithm) throws HashGenerationException;
    String computeSHA256(String unsignedDocument) throws HashGenerationException;
    byte[] sha256Digest(byte[] input) throws HashGenerationException;
}
