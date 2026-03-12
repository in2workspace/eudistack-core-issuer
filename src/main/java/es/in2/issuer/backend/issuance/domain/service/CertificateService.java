package es.in2.issuer.backend.issuance.domain.service;

import reactor.core.publisher.Mono;

public interface CertificateService {
    Mono<String> getOrganizationIdFromCertificate(String cert);
}
