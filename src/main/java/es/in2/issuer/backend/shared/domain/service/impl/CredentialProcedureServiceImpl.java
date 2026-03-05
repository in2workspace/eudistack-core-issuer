package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.FormatUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingCredentialTypeException;
import es.in2.issuer.backend.shared.domain.exception.NoCredentialFoundException;
import es.in2.issuer.backend.shared.domain.exception.ParseCredentialJsonException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.stereotype.Service;
import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialProcedureServiceImpl implements CredentialProcedureService {

    private final IssuerProperties appConfig;
    private static final String UPDATED_CREDENTIAL = "Updated credential";
    private final CredentialProcedureRepository credentialProcedureRepository;
    private final ObjectMapper objectMapper;
    private final R2dbcEntityTemplate r2dbcEntityTemplate;
    private final CredentialProfileRegistry credentialProfileRegistry;

    @Override
    public Mono<CredentialProcedure> createCredentialProcedure(CredentialProcedureCreationRequest request) {
        CredentialProcedure credentialProcedure = CredentialProcedure.builder()
                .procedureId(UUID.fromString(request.procedureId()))
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialDataSet(request.credentialDataSet())
                .credentialFormat(request.credentialFormat())
                .organizationIdentifier(request.organizationIdentifier())
                .credentialType(request.credentialType())
                .subject(request.subject())
                .validUntil(request.validUntil())
                .email(request.email())
                .delivery(request.delivery())
                .refreshToken(UUID.randomUUID().toString())
                .build();
        return r2dbcEntityTemplate.insert(credentialProcedure)
                .doOnSuccess(saved -> log.info("Created credential procedure: {}", saved.getProcedureId()))
                .doOnError(e -> log.error("Error saving credential procedure", e));
    }

    @Override
    public Mono<String> getCredentialTypeByProcedureId(String procedureId) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(this::getCredentialType);
    }

    private Mono<String> getCredentialType(CredentialProcedure credentialProcedure) {
        try {
            JsonNode credential = objectMapper.readTree(credentialProcedure.getCredentialDataSet());
            JsonNode typeNode = credential.has(VC) ? credential.get(VC).get(TYPE) : credential.get(TYPE);

            return extractCredentialType(typeNode)
                    .map(Mono::just)
                    .orElseGet(Mono::empty);
        } catch (JsonProcessingException e) {
            return Mono.error(new ParseCredentialJsonException("Error parsing credential"));
        }
    }

    @Override
    public Mono<JsonNode> getCredentialNode(CredentialProcedure credentialProcedure) {
        return Mono.defer(() -> {
            if (credentialProcedure == null || credentialProcedure.getCredentialDataSet() == null) {
                return Mono.error(new ParseCredentialJsonException("CredentialProcedure or credentialDataSet is null"));
            }

            try {
                JsonNode credential = objectMapper.readTree(credentialProcedure.getCredentialDataSet());
                return Mono.just(credential);
            } catch (JsonProcessingException e) {
                return Mono.error(new ParseCredentialJsonException("Error parsing credential JSON"));
            }
        });
    }

    @Override
    public Mono<String> getCredentialId(CredentialProcedure credentialProcedure) {
        return getCredentialNode(credentialProcedure)
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
    public Mono<Void> updateCredentialDataSetByProcedureId(String procedureId, String credentialDataSet, String format) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    credentialProcedure.setCredentialDataSet(credentialDataSet);
                    credentialProcedure.setCredentialStatus(CredentialStatusEnum.ISSUED);
                    credentialProcedure.setCredentialFormat(format);

                    return credentialProcedureRepository.save(credentialProcedure)
                            .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                            .then();
                });
    }

    @Override
    public Mono<Void> updateCredentialDataSetByProcedureId(String procedureId, String credentialDataSet) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    credentialProcedure.setCredentialDataSet(credentialDataSet);
                    credentialProcedure.setCredentialStatus(CredentialStatusEnum.ISSUED);

                    return credentialProcedureRepository.save(credentialProcedure)
                            .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                            .then();
                });
    }

    @Override
    public Mono<String> getCredentialDataSetByProcedureId(String procedureId) {
        return credentialProcedureRepository.findById(UUID.fromString(procedureId))
                .map(CredentialProcedure::getCredentialDataSet);
    }

    @Override
    public Mono<String> getCredentialStatusByProcedureId(String procedureId) {
        log.debug("Getting credential status for procedureId: {}", procedureId);
        return credentialProcedureRepository.findCredentialStatusByProcedureId(UUID.fromString(procedureId));
    }

    @Override
    public Flux<String> getAllIssuedCredentialByOrganizationIdentifier(String organizationIdentifier) {
        return credentialProcedureRepository.findByCredentialStatusAndOrganizationIdentifier(CredentialStatusEnum.ISSUED, organizationIdentifier)
                .map(CredentialProcedure::getCredentialDataSet);
    }

    @Override
    public Mono<CredentialDetails> getProcedureDetailByProcedureIdAndOrganizationId(String organizationIdentifier, String procedureId, boolean sysAdmin) {
        Mono<CredentialProcedure> credentialProcedureMono;
        if (sysAdmin) {
            log.debug("Admin access for procedureId: {}", procedureId);
            credentialProcedureMono = credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "*"));
        } else {
            credentialProcedureMono = credentialProcedureRepository.findByProcedureIdAndOrganizationIdentifier(UUID.fromString(procedureId), organizationIdentifier);
        }
        return credentialProcedureMono
                .switchIfEmpty(Mono.error(new NoCredentialFoundException("No credential found for procedureId: " + procedureId)))
                .flatMap(credentialProcedure -> {
                    try {
                        return Mono.just(CredentialDetails.builder()
                                .procedureId(credentialProcedure.getProcedureId())
                                .lifeCycleStatus(String.valueOf(credentialProcedure.getCredentialStatus()))
                                .credential(objectMapper.readTree(credentialProcedure.getCredentialDataSet()))
                                .email(credentialProcedure.getEmail())
                                .build());
                    } catch (JsonProcessingException e) {
                        log.warn(PARSING_CREDENTIAL_ERROR_MESSAGE, e);
                        return Mono.error(new JsonParseException(null, PARSING_CREDENTIAL_ERROR_MESSAGE));
                    }
                })
                .doOnError(error -> log.error("Could not load credentials, error: {}", error.getMessage()));
    }

    @Override
    public Mono<Void> updateCredentialProcedureCredentialStatusToValidByProcedureId(String procedureId) {
        return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    log.debug("Updating credential status to VALID for procedureId: {}", procedureId);
                    credentialProcedure.setCredentialStatus(CredentialStatusEnum.VALID);
                    return credentialProcedureRepository.save(credentialProcedure)
                            .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                            .then();
                });
    }

    @Override
    public Mono<Void> updateCredentialProcedureCredentialStatusToRevoke(CredentialProcedure credentialProcedure) {
        credentialProcedure.setCredentialStatus(CredentialStatusEnum.REVOKED);
        return credentialProcedureRepository.save(credentialProcedure)
                .doOnSuccess(result -> log.info(UPDATED_CREDENTIAL))
                .then();
    }

    @Override
    public Mono<CredentialProcedures> getAllProceduresBasicInfoByOrganizationId(String organizationIdentifier) {
        return credentialProcedureRepository.findAllByOrganizationIdentifier(organizationIdentifier)
                .map(cp -> {
                    try {
                        return toProcedureBasicInfo(cp);
                    } catch (ParseCredentialJsonException e) {
                        throw Exceptions.propagate(e);
                    }
                })
                .map(procedureBasicInfo ->
                        CredentialProcedures.CredentialProcedure.builder()
                                .credentialProcedure(procedureBasicInfo)
                                .build())
                .collectList()
                .map(CredentialProcedures::new);
    }

    @Override
    public Mono<CredentialProcedures> getAllProceduresVisibleFor(String organizationIdentifier, boolean sysAdmin) {
        if (sysAdmin) {
            return getAllProceduresBasicInfoForAllOrganizations()
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "*"));
        }
        return getAllProceduresBasicInfoByOrganizationId(organizationIdentifier);
    }

    private Mono<CredentialProcedures> getAllProceduresBasicInfoForAllOrganizations() {
        return credentialProcedureRepository.findAllOrderByUpdatedDesc()
                .map(cp -> {
                    try {
                        return toProcedureBasicInfo(cp);
                    } catch (ParseCredentialJsonException e) {
                        throw Exceptions.propagate(e);
                    }
                })
                .map(procedureBasicInfo -> CredentialProcedures.CredentialProcedure.builder()
                        .credentialProcedure(procedureBasicInfo)
                        .build())
                .collectList()
                .map(CredentialProcedures::new);
    }

    private ProcedureBasicInfo toProcedureBasicInfo(CredentialProcedure cp) throws ParseCredentialJsonException {
        try {
            objectMapper.readTree(cp.getCredentialDataSet());
        } catch (JsonProcessingException e) {
            throw new ParseCredentialJsonException("Invalid credential JSON");
        }

        return ProcedureBasicInfo.builder()
                .procedureId(cp.getProcedureId())
                .subject(cp.getSubject())
                .credentialType(cp.getCredentialType())
                .status(String.valueOf(cp.getCredentialStatus()))
                .organizationIdentifier(cp.getOrganizationIdentifier())
                .updated(cp.getUpdatedAt())
                .build();
    }

    @Override
    public Mono<CredentialProcedure> getCredentialProcedureById(String procedureId) {
        return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId));
    }

    @Override
    public Mono<CredentialProcedure> getCredentialProcedureByNotificationId(String notificationId) {
        return credentialProcedureRepository.findByNotificationId(UUID.fromString(notificationId));
    }

    @Override
    public Mono<String> getNotificationIdByProcedureId(String procedureId) {
        return credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId))
                .map(cp -> cp.getNotificationId().toString());
    }

    @Override
    public Mono<CredentialProcedure> getCredentialProcedureByRefreshToken(String refreshToken) {
        return credentialProcedureRepository.findByRefreshToken(refreshToken);
    }

    @Override
    public Mono<CredentialOfferEmailNotificationInfo> getCredentialOfferEmailInfoByProcedureId(String procedureId) {
        return credentialProcedureRepository
                .findByProcedureId(UUID.fromString(procedureId))
                .flatMap(credentialProcedure -> {
                    String credentialType = resolveCredentialType(credentialProcedure.getCredentialType());
                    return switch (credentialType) {
                        case LEAR_CREDENTIAL_EMPLOYEE -> Mono.fromCallable(() ->
                                        objectMapper.readTree(credentialProcedure.getCredentialDataSet())
                                )
                                .map(credential -> {
                                    String org = credential
                                            .get(CREDENTIAL_SUBJECT)
                                            .get(MANDATE)
                                            .get(MANDATOR)
                                            .get(ORGANIZATION)
                                            .asText();
                                    return new CredentialOfferEmailNotificationInfo(
                                            credentialProcedure.getEmail(),
                                            org
                                    );
                                })
                                .onErrorMap(JsonProcessingException.class, e ->
                                        new ParseCredentialJsonException(
                                                "Error parsing credential for procedureId: " + procedureId
                                        )
                                );
                        case LEAR_CREDENTIAL_MACHINE -> Mono.fromCallable(() ->
                                        objectMapper.readTree(credentialProcedure.getCredentialDataSet())
                                )
                                .map(credential -> {
                                    String org = credential
                                            .get(CREDENTIAL_SUBJECT)
                                            .get(MANDATE)
                                            .get(MANDATOR)
                                            .get(ORGANIZATION)
                                            .asText();
                                    return new CredentialOfferEmailNotificationInfo(
                                            credentialProcedure.getEmail(),
                                            org
                                    );
                                })
                                .onErrorMap(JsonProcessingException.class, e ->
                                        new ParseCredentialJsonException(
                                                "Error parsing credential for procedureId: " + procedureId
                                        )
                                );
                        case LABEL_CREDENTIAL -> Mono.just(
                                new CredentialOfferEmailNotificationInfo(
                                        credentialProcedure.getEmail(),
                                        appConfig.getSysTenant()
                                )
                        );
                        default -> Mono.error(new FormatUnsupportedException(
                                "Unknown credential type: " + credentialType + " (configId: " + credentialProcedure.getCredentialType() + ")"
                        ));
                    };
                });
    }

    private String resolveCredentialType(String credentialConfigurationId) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        if (profile != null) {
            return profile.credentialType();
        }
        return credentialConfigurationId;
    }

}
