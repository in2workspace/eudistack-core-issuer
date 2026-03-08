package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialStatusTransitionException;
import es.in2.issuer.backend.shared.domain.exception.MissingCredentialTypeException;
import es.in2.issuer.backend.shared.domain.exception.NoCredentialFoundException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.stereotype.Service;
import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class IssuanceServiceImpl implements IssuanceService {

    private final IssuerProperties appConfig;
    private static final String UPDATED_CREDENTIAL = "Updated credential";
    private final IssuanceRepository issuanceRepository;
    private final ObjectMapper objectMapper;
    private final R2dbcEntityTemplate r2dbcEntityTemplate;
    private final CredentialProfileRegistry credentialProfileRegistry;

    @Override
    public Mono<Issuance> saveIssuance(Issuance issuance) {
        return r2dbcEntityTemplate.insert(issuance)
                .doOnSuccess(saved -> log.info("Created issuance: {}", saved.getIssuanceId()))
                .doOnError(e -> log.error("Error saving issuance", e));
    }

    @Override
    public Mono<String> getCredentialTypeByIssuanceId(String issuanceId) {
        return issuanceRepository.findById(UUID.fromString(issuanceId))
                .flatMap(this::getCredentialType);
    }

    private Mono<String> getCredentialType(Issuance issuance) {
        try {
            JsonNode credential = objectMapper.readTree(issuance.getCredentialDataSet());
            JsonNode typeNode = credential.has(VC) ? credential.get(VC).get(TYPE) : credential.get(TYPE);

            return extractCredentialType(typeNode)
                    .map(Mono::just)
                    .orElseGet(Mono::empty);
        } catch (JsonProcessingException e) {
            return Mono.error(new ParseCredentialJsonException("Error parsing credential"));
        }
    }

    @Override
    public Mono<JsonNode> extractCredentialNode(Issuance issuance) {
        return Mono.defer(() -> {
            if (issuance == null || issuance.getCredentialDataSet() == null) {
                return Mono.error(new ParseCredentialJsonException("Issuance or credentialDataSet is null"));
            }

            try {
                JsonNode credential = objectMapper.readTree(issuance.getCredentialDataSet());
                return Mono.just(credential);
            } catch (JsonProcessingException e) {
                return Mono.error(new ParseCredentialJsonException("Error parsing credential JSON"));
            }
        });
    }

    @Override
    public Mono<String> extractCredentialId(Issuance issuance) {
        return extractCredentialNode(issuance)
                .map(node -> {
                    String credentialId = node.path(VC).path(ID).asText(null);

                    if (credentialId == null || credentialId.isBlank()) {
                        credentialId = node.path(ID).asText(null);
                    }

                    return credentialId;
                })
                .filter(id -> id != null && !id.isBlank())
                .switchIfEmpty(Mono.error(new ParseCredentialJsonException(
                        "Missing credential id (expected vc.id or id)")));
    }

    private Optional<String> extractCredentialType(JsonNode typeNode) {
        if (typeNode == null || !typeNode.isArray()) {
            throw new MissingCredentialTypeException("The credential type is missing");
        }

        for (JsonNode type : typeNode) {
            String typeText = type.asText();
            if (!typeText.equals(VERIFIABLE_CREDENTIAL) && !typeText.equals(VERIFIABLE_ATTESTATION)) {
                return Optional.of(typeText);
            }
        }

        return Optional.empty();
    }

    @Override
    public Mono<Void> updateCredentialDataSetByIssuanceId(String issuanceId, String credentialDataSet, String format) {
        return issuanceRepository.findById(UUID.fromString(issuanceId))
                .flatMap(issuance -> {
                    validateTransition(issuance.getCredentialStatus(), CredentialStatusEnum.ISSUED);
                    issuance.setCredentialDataSet(credentialDataSet);
                    issuance.setCredentialStatus(CredentialStatusEnum.ISSUED);
                    issuance.setCredentialFormat(format);

                    return issuanceRepository.save(issuance)
                            .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                            .then();
                });
    }


    @Override
    public Mono<String> getCredentialDataSetByIssuanceId(String issuanceId) {
        return issuanceRepository.findById(UUID.fromString(issuanceId))
                .map(Issuance::getCredentialDataSet);
    }

    @Override
    public Mono<String> getCredentialStatusByIssuanceId(String issuanceId) {
        log.debug("Getting credential status for issuanceId: {}", issuanceId);
        return issuanceRepository.findCredentialStatusByIssuanceId(UUID.fromString(issuanceId));
    }

    @Override
    public Flux<String> getAllIssuedCredentialByOrganizationIdentifier(String organizationIdentifier) {
        return issuanceRepository.findByCredentialStatusAndOrganizationIdentifier(CredentialStatusEnum.ISSUED, organizationIdentifier)
                .map(Issuance::getCredentialDataSet);
    }

    @Override
    public Mono<CredentialDetails> getIssuanceDetailByIssuanceIdAndOrganizationId(String organizationIdentifier, String issuanceId, boolean sysAdmin) {
        Mono<Issuance> issuanceMono;
        if (sysAdmin) {
            log.debug("Admin access for issuanceId: {}", issuanceId);
            issuanceMono = issuanceRepository.findByIssuanceId(UUID.fromString(issuanceId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "*"));
        } else {
            issuanceMono = issuanceRepository.findByIssuanceIdAndOrganizationIdentifier(UUID.fromString(issuanceId), organizationIdentifier);
        }
        return issuanceMono
                .switchIfEmpty(Mono.error(new NoCredentialFoundException("No credential found for issuanceId: " + issuanceId)))
                .flatMap(issuance -> {
                    try {
                        return Mono.just(CredentialDetails.builder()
                                .issuanceId(issuance.getIssuanceId())
                                .lifeCycleStatus(String.valueOf(issuance.getCredentialStatus()))
                                .credential(objectMapper.readTree(issuance.getCredentialDataSet()))
                                .email(issuance.getEmail())
                                .build());
                    } catch (JsonProcessingException e) {
                        log.warn(PARSING_CREDENTIAL_ERROR_MESSAGE, e);
                        return Mono.error(new JsonParseException(null, PARSING_CREDENTIAL_ERROR_MESSAGE));
                    }
                })
                .doOnError(error -> log.error("Could not load credentials, error: {}", error.getMessage()));
    }

    @Override
    public Mono<Void> updateIssuanceStatusToValidByIssuanceId(String issuanceId) {
        return issuanceRepository.findByIssuanceId(UUID.fromString(issuanceId))
                .flatMap(issuance -> {
                    validateTransition(issuance.getCredentialStatus(), CredentialStatusEnum.VALID);
                    log.debug("Updating credential status to VALID for issuanceId: {}", issuanceId);
                    issuance.setCredentialStatus(CredentialStatusEnum.VALID);
                    return issuanceRepository.save(issuance)
                            .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                            .then();
                });
    }

    @Override
    public Mono<Void> updateIssuanceStatusToRevoked(Issuance issuance) {
        validateTransition(issuance.getCredentialStatus(), CredentialStatusEnum.REVOKED);
        issuance.setCredentialStatus(CredentialStatusEnum.REVOKED);
        return issuanceRepository.save(issuance)
                .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                .then();
    }

    @Override
    public Mono<Void> withdrawIssuance(String issuanceId) {
        return issuanceRepository.findByIssuanceId(UUID.fromString(issuanceId))
                .flatMap(issuance -> {
                    validateTransition(issuance.getCredentialStatus(), CredentialStatusEnum.WITHDRAWN);
                    log.debug("Withdrawing issuance: {}", issuanceId);
                    issuance.setCredentialStatus(CredentialStatusEnum.WITHDRAWN);
                    return issuanceRepository.save(issuance)
                            .doOnSuccess(result -> log.info("Issuance withdrawn: {}", issuanceId))
                            .then();
                });
    }

    @Override
    public Mono<IssuanceList> getAllIssuanceSummariesByOrganizationId(String organizationIdentifier) {
        return toIssuanceList(issuanceRepository.findAllByOrganizationIdentifier(organizationIdentifier));
    }

    @Override
    public Mono<IssuanceList> getAllIssuancesVisibleFor(String organizationIdentifier, boolean sysAdmin) {
        if (sysAdmin) {
            return toIssuanceList(issuanceRepository.findAllOrderByUpdatedDesc())
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "*"));
        }
        return getAllIssuanceSummariesByOrganizationId(organizationIdentifier);
    }

    private Mono<IssuanceList> toIssuanceList(Flux<Issuance> source) {
        return source
                .map(issuance -> {
                    try {
                        return toIssuanceSummary(issuance);
                    } catch (ParseCredentialJsonException e) {
                        throw Exceptions.propagate(e);
                    }
                })
                .map(info -> IssuanceList.IssuanceEntry.builder()
                        .issuance(info)
                        .build())
                .collectList()
                .map(IssuanceList::new);
    }

    private IssuanceSummary toIssuanceSummary(Issuance issuance) throws ParseCredentialJsonException {
        try {
            objectMapper.readTree(issuance.getCredentialDataSet());
        } catch (JsonProcessingException e) {
            throw new ParseCredentialJsonException("Invalid credential JSON");
        }

        return IssuanceSummary.builder()
                .issuanceId(issuance.getIssuanceId())
                .subject(issuance.getSubject())
                .credentialType(issuance.getCredentialType())
                .status(String.valueOf(issuance.getCredentialStatus()))
                .organizationIdentifier(issuance.getOrganizationIdentifier())
                .updated(issuance.getUpdatedAt())
                .build();
    }

    @Override
    public Mono<Issuance> getIssuanceById(String issuanceId) {
        return issuanceRepository.findByIssuanceId(UUID.fromString(issuanceId));
    }

    @Override
    public Mono<Issuance> getIssuanceByCredentialOfferRefreshToken(String credentialOfferRefreshToken) {
        return issuanceRepository.findByCredentialOfferRefreshToken(credentialOfferRefreshToken);
    }

    @Override
    public Mono<CredentialOfferEmailNotificationInfo> findCredentialOfferEmailInfoByIssuanceId(String issuanceId) {
        return issuanceRepository
                .findByIssuanceId(UUID.fromString(issuanceId))
                .flatMap(issuance -> {
                    String configId = issuance.getCredentialType();
                    CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
                    if (profile == null) {
                        return Mono.error(new FormatUnsupportedException(
                                "Unknown credential configuration: " + configId));
                    }

                    // If the profile has organization extraction, use it to get the org name
                    if (profile.organizationExtraction() != null
                            && !"none".equals(profile.organizationExtraction().strategy())) {
                        return extractOrganizationFromCredential(issuance, issuanceId);
                    }

                    // No organization extraction (e.g., label credentials) → use system tenant
                    return Mono.just(new CredentialOfferEmailNotificationInfo(
                            issuance.getEmail(),
                            appConfig.getSysTenant()
                    ));
                });
    }

    private Mono<CredentialOfferEmailNotificationInfo> extractOrganizationFromCredential(
            Issuance issuance, String issuanceId) {
        return Mono.fromCallable(() ->
                        objectMapper.readTree(issuance.getCredentialDataSet())
                )
                .map(credential -> {
                    // W3C: credentialSubject.mandate.mandator.organization
                    // SD-JWT: mandator.organization (top-level claim)
                    JsonNode mandator = credential.has(CREDENTIAL_SUBJECT)
                            ? credential.get(CREDENTIAL_SUBJECT).get(MANDATE).get(MANDATOR)
                            : credential.get(MANDATOR);
                    String org = mandator.get(ORGANIZATION).asText();
                    return new CredentialOfferEmailNotificationInfo(
                            issuance.getEmail(),
                            org
                    );
                })
                .onErrorMap(JsonProcessingException.class, e ->
                        new ParseCredentialJsonException(
                                "Error parsing credential for issuanceId: " + issuanceId
                        )
                );
    }

    @Override
    public Flux<Issuance> findIssuedReadyForActivation(Instant now) {
        return issuanceRepository.findIssuedReadyForActivation(CredentialStatusEnum.ISSUED, now);
    }

    @Override
    public Flux<Issuance> findStaleDrafts(Instant cutoff) {
        return issuanceRepository.findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum.DRAFT, cutoff);
    }

    @Override
    public Mono<Issuance> updateIssuance(Issuance issuance) {
        return issuanceRepository.save(issuance);
    }

    private void validateTransition(CredentialStatusEnum from, CredentialStatusEnum to) {
        if (!from.canTransitionTo(to)) {
            throw new InvalidCredentialStatusTransitionException(from, to);
        }
    }

}
