package es.in2.issuer.backend.signing.domain.service.impl;

import java.util.*;
import java.time.Duration;
import java.time.Instant;
import es.in2.issuer.backend.shared.domain.exception.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.infrastructure.util.HttpUtils;
import es.in2.issuer.backend.signing.domain.exception.OrganizationIdentifierNotFoundException;
import es.in2.issuer.backend.signing.domain.model.dto.CacheEntry;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import es.in2.issuer.backend.signing.domain.spi.QtspAuthPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.signing.domain.util.PathConstants.INFO_PATH;
import static es.in2.issuer.backend.signing.domain.util.PathConstants.LIST_PATH;

@Slf4j
@Service
@RequiredArgsConstructor
public class QtspIssuerServiceImpl implements QtspIssuerService {

    private final ObjectMapper objectMapper;
    private final QtspAuthPort qtspAuthClient;
    private final RuntimeSigningConfig runtimeSigningConfig;
    private final ConcurrentMap<String, CacheEntry> certificateInfoCache= new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Mono<String>> certificateInfoInFlight = new ConcurrentHashMap<>();
    private final HttpUtils httpUtils;

    private static final String CERTIFICATES = "certificates";
    private static final String CERT_INFO = "certInfo";
    private static final String AUTH_INFO = "authInfo";
    private static final String CREDENTIAL_INFO = "credentialInfo";
    private static final String ONLY_VALID = "onlyValid";
    private static final String LANG = "lang";
    private static final String CLIENT_DATA = "clientData";
    private static final String CREDENTIAL_IDS =  "credentialIDs";
    private static final String SERIALIZING_ERROR = "Error serializing request body to JSON";


    private RemoteSignatureDto remoteCfgRequired() {
        RemoteSignatureDto cfg = runtimeSigningConfig.getRemoteSignature();
        if (cfg == null) {
            throw new IllegalStateException("Remote signature config not pushed (runtimeSigningConfig.remoteSignature is null)");
        }
        return cfg;
    }

    private Duration certificateInfoCacheTtl() {
        RemoteSignatureDto cfg = remoteCfgRequired();
        if (cfg.certificateInfoCacheTtl() == null || cfg.certificateInfoCacheTtl().isBlank()) {
            return Duration.ofMinutes(10);
        }
        return Duration.parse(cfg.certificateInfoCacheTtl()); // ISO-8601: PT10M
    }

    @Override
    public Mono<Boolean> validateCredentials() {
        SigningRequest signatureRequest = SigningRequest.builder().build();
        return qtspAuthClient.requestAccessToken(signatureRequest, SIGNATURE_REMOTE_SCOPE_SERVICE)
                .flatMap(this::validateCertificate);
    }

    @Override
    public Mono<String> requestCertificateInfo(String accessToken, String credentialID) {
        CacheEntry cached = certificateInfoCache.get(credentialID);
        if (cached != null && cached.expiresAt().isAfter(Instant.now())) {
            return Mono.just(cached.value());
        }

        Mono<String> existing = certificateInfoInFlight.get(credentialID);
        if (existing != null) {
            return existing;
        }

        Mono<String> refreshMono =
                fetchCertificateInfoFromQtsp(accessToken, credentialID)
                        .doOnNext(body -> {
                            Instant expiresAt = Instant.now().plus(certificateInfoCacheTtl());
                            certificateInfoCache.put(credentialID, new CacheEntry(body, expiresAt));
                        })
                        .doFinally(ignored -> certificateInfoInFlight.remove(credentialID))
                        .cache();

        Mono<String> winner = certificateInfoInFlight.putIfAbsent(credentialID, refreshMono);
        return winner != null ? winner : refreshMono;
    }

    private Mono<String> fetchCertificateInfoFromQtsp(String accessToken, String credentialID) {
        RemoteSignatureDto cfg = remoteCfgRequired();
        String credentialsInfoEndpoint = cfg.url() + INFO_PATH;
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put(CREDENTIAL_ID, credentialID);
        requestBody.put(CERTIFICATES, "chain");
        requestBody.put(CERT_INFO, "true");
        requestBody.put(AUTH_INFO, "true");

        String requestBodySignature;
        try {
            requestBodySignature = objectMapper.writeValueAsString(requestBody);
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException(SERIALIZING_ERROR, e));
        }
        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        return httpUtils.postRequest(credentialsInfoEndpoint, headers, requestBodySignature)
                .doOnError(error -> log.error("Error sending credential to sign: {}", error.getMessage()));
    }

    @Override
    public Mono<DetailedIssuer> extractIssuerFromCertificateInfo(String certificateInfo) {
        try {
            log.info("Starting extraction of issuer from certificate info");
            JsonNode certNode = objectMapper.readTree(certificateInfo).get("cert");
            if (certNode == null) {
                return Mono.error(new OrganizationIdentifierNotFoundException("Missing 'cert' section in certificate info"));
            }
            String subjectDN = certNode.get("subjectDN").asText();
            String serialNumber = certNode.get("serialNumber").asText();
            Map<String, String> dnAttributes = parseDnAttributes(subjectDN);
            JsonNode certificatesArray = certNode.get(CERTIFICATES);

            return extractOrganizationIdentifier(certificatesArray)
                    .switchIfEmpty(Mono.error(new OrganizationIdentifierNotFoundException("organizationIdentifier not found in the certificate.")))
                    .map(orgId -> DetailedIssuer.builder()
                            .id(DID_ELSI + orgId)
                            .organizationIdentifier(orgId)
                            .organization(dnAttributes.get("O"))
                            .country(dnAttributes.get("C"))
                            .commonName(dnAttributes.get("CN"))
                            .serialNumber(serialNumber)
                            .build());
        } catch (JsonProcessingException e) {
            return Mono.error(new OrganizationIdentifierNotFoundException("Error parsing certificate info: " + e.getMessage()));
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

    private Mono<String> extractOrganizationIdentifier(JsonNode certificatesArray) {
        if (certificatesArray == null || !certificatesArray.isArray()) {
            return Mono.empty();
        }
        return Flux.fromIterable(certificatesArray)
                .concatMap(certNodeEntry -> extractOrgFromCertEntry(certNodeEntry.asText()))
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

    @Override
    public boolean isServerMode() {
        RemoteSignatureDto cfg = remoteCfgRequired();
        return SIGNATURE_REMOTE_TYPE_SERVER.equals(cfg.type());
    }

    @Override
    public Mono<DetailedIssuer> resolveRemoteDetailedIssuer() {
        return validateCredentials()
                .flatMap(valid -> {
                    if (Boolean.FALSE.equals(valid)) {
                        return Mono.error(new RemoteSignatureException("Credentials mismatch."));
                    }
                    return qtspAuthClient.requestAccessToken(null, SIGNATURE_REMOTE_SCOPE_SERVICE)
                            .flatMap(token -> requestCertificateInfo(token, getCredentialId()))
                            .flatMap(this::extractIssuerFromCertificateInfo);
                });
    }

    @Override
    public String getCredentialId() {
        return remoteCfgRequired().credentialId();
    }

    private Mono<Boolean> validateCertificate(String accessToken) {
        RemoteSignatureDto cfg = remoteCfgRequired();
        String credentialID = cfg.credentialId();
        String credentialListEndpoint = cfg.url() + LIST_PATH;

        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put(CREDENTIAL_INFO, true);
        requestBody.put(CERTIFICATES, "chain");
        requestBody.put(CERT_INFO, true);
        requestBody.put(AUTH_INFO, true);
        requestBody.put(ONLY_VALID, true);
        requestBody.put(LANG, 0);
        requestBody.put(CLIENT_DATA, "string");
        try {
            String requestBodyJson = objectMapper.writeValueAsString(requestBody);
            return httpUtils.postRequest(credentialListEndpoint, headers, requestBodyJson)
                    .flatMap(responseJson -> {
                        try {
                            Map<String, List<String>> responseMap = objectMapper.readValue(responseJson, Map.class);
                            List<String> receivedCredentialIDs = responseMap.get(CREDENTIAL_IDS);
                            boolean isValid = receivedCredentialIDs != null &&
                                    receivedCredentialIDs.stream()
                                            .anyMatch(id -> id.trim().equalsIgnoreCase(credentialID.trim()));
                            return Mono.just(isValid);
                        } catch (JsonProcessingException e) {
                            return Mono.error(new RemoteSignatureException("Error parsing certificate list response", e));
                        }
                    })
                    .switchIfEmpty(Mono.just(false))
                    .doOnError(error -> log.error("Error validating certificate: {}", error.getMessage()));
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException(SERIALIZING_ERROR, e));
        }
    }

    private Mono<String> extractOrgFromX509(byte[] decodedBytes) {
        return Mono.defer(() -> {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedBytes));
                String certAsString = x509Certificate.toString();
                Pattern certPattern = Pattern.compile("OID\\.2\\.5\\.4\\.97=([^,\\s]+)");
                Matcher certMatcher = certPattern.matcher(certAsString);
                if (certMatcher.find()) {
                    String orgId = certMatcher.group(1);
                    return Mono.just(orgId);
                } else {
                    return Mono.empty();
                }
            } catch (Exception e) {
                log.debug("Error parsing certificate: {}", e.getMessage());
                return Mono.empty();
            }
        });
    }

}
