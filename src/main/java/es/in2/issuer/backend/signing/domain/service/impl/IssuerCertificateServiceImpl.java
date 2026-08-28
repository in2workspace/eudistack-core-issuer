package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.signing.domain.exception.OrganizationIdentifierNotFoundException;
import es.in2.issuer.backend.signing.domain.model.dto.CacheEntry;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.service.IssuerCertificateService;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.shared.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_SERVICE;

@Slf4j
@Service
@RequiredArgsConstructor
public class IssuerCertificateServiceImpl implements IssuerCertificateService {

    private final CscPort cscPort;

    // NOTE: keyed by bare credentialId — not unique across tenants (known limitation, tracked separately)
    private final ConcurrentMap<String, CacheEntry<CertificateInfo>> certificateInfoCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Mono<CertificateInfo>> certificateInfoInFlight = new ConcurrentHashMap<>();

    @Override
    public Mono<Boolean> validateCredentials(RemoteSignatureDto cfg) {
        return cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_SERVICE, true)
                .flatMap(accessToken -> cscPort.validateCredentialId(cfg, accessToken, cfg.credentialId()));
    }

    @Override
    public Mono<CertificateInfo> requestCertificateInfo(RemoteSignatureDto cfg, String accessToken, String credentialId) {
        CacheEntry<CertificateInfo> cached = certificateInfoCache.get(credentialId);
        if (cached != null && cached.expiresAt().isAfter(Instant.now())) {
            return Mono.just(cached.value());
        }

        Mono<CertificateInfo> existing = certificateInfoInFlight.get(credentialId);
        if (existing != null) {
            return existing;
        }

        Mono<CertificateInfo> refreshMono = cscPort.getCredentialInfo(cfg, accessToken, credentialId)
                .doOnNext(info -> {
                    Instant expiresAt = Instant.now().plus(cacheTtl(cfg));
                    certificateInfoCache.put(credentialId, new CacheEntry<>(info, expiresAt));
                })
                .doFinally(ignored -> certificateInfoInFlight.remove(credentialId))
                .cache();

        Mono<CertificateInfo> winner = certificateInfoInFlight.putIfAbsent(credentialId, refreshMono);
        return winner != null ? winner : refreshMono;
    }

    @Override
    public Mono<DetailedIssuer> resolveRemoteDetailedIssuer(RemoteSignatureDto cfg) {
        return validateCredentials(cfg)
                .flatMap(valid -> {
                    if (Boolean.FALSE.equals(valid)) {
                        return Mono.error(new RemoteSignatureException("Credentials mismatch."));
                    }
                    return cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_SERVICE, true)
                            .flatMap(token -> requestCertificateInfo(cfg, token, cfg.credentialId()))
                            .flatMap(this::extractIssuerFromCertificateInfo);
                });
    }

    private Mono<DetailedIssuer> extractIssuerFromCertificateInfo(CertificateInfo certInfo) {
        try {
            log.info("Extracting issuer from certificate info");
            Map<String, String> dnAttributes = parseDnAttributes(certInfo.subjectDN());
            return extractOrganizationIdentifier(certInfo.certificates())
                    .switchIfEmpty(Mono.error(new OrganizationIdentifierNotFoundException(
                            "organizationIdentifier not found in the certificate.")))
                    .map(orgId -> DetailedIssuer.builder()
                            .id("did:elsi:" + orgId)
                            .organizationIdentifier(orgId)
                            .organization(dnAttributes.get("O"))
                            .country(dnAttributes.get("C"))
                            .commonName(dnAttributes.get("CN"))
                            .serialNumber(certInfo.serialNumber())
                            .build());
        } catch (InvalidNameException e) {
            return Mono.error(new OrganizationIdentifierNotFoundException("Error parsing subjectDN: " + e.getMessage()));
        }
    }

    private Map<String, String> parseDnAttributes(String subjectDN) throws InvalidNameException {
        LdapName ldapDN = new LdapName(subjectDN);
        Map<String, String> dnAttributes = new HashMap<>();
        for (Rdn rdn : ldapDN.getRdns()) {
            dnAttributes.put(rdn.getType(), rdn.getValue().toString());
        }
        return dnAttributes;
    }

    private Mono<String> extractOrganizationIdentifier(List<String> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return Mono.empty();
        }
        return Flux.fromIterable(certificates)
                .concatMap(this::extractOrgFromCertEntry)
                .next();
    }

    private Mono<String> extractOrgFromCertEntry(String base64Cert) {
        byte[] decodedBytes;
        try {
            decodedBytes = Base64.getDecoder().decode(base64Cert);
        } catch (IllegalArgumentException e) {
            log.warn("Skipping certificate with invalid Base64 encoding: {}", e.getMessage());
            return Mono.empty();
        }

        String decodedCert = new String(decodedBytes, StandardCharsets.UTF_8);
        Pattern pattern = Pattern.compile("organizationIdentifier\\s*=\\s*([\\w\\-]+)");
        Matcher matcher = pattern.matcher(decodedCert);
        if (matcher.find()) {
            return Mono.just(matcher.group(1));
        }
        return extractOrgFromX509(decodedBytes);
    }

    private Mono<String> extractOrgFromX509(byte[] decodedBytes) {
        return Mono.defer(() -> {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedBytes));
                Pattern certPattern = Pattern.compile("OID\\.2\\.5\\.4\\.97=([^,\\s]+)");
                Matcher certMatcher = certPattern.matcher(x509.toString());
                if (certMatcher.find()) {
                    return Mono.just(certMatcher.group(1));
                }
                return Mono.empty();
            } catch (Exception e) {
                log.debug("Error parsing certificate: {}", e.getMessage());
                return Mono.empty();
            }
        });
    }

    private static Duration cacheTtl(RemoteSignatureDto cfg) {
        if (cfg.certificateInfoCacheTtl() == null || cfg.certificateInfoCacheTtl().isBlank()) {
            return Duration.ofMinutes(10);
        }
        return Duration.parse(cfg.certificateInfoCacheTtl());
    }
}
