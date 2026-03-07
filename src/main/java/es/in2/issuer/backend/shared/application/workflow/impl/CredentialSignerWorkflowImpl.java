package es.in2.issuer.backend.shared.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.Base45Exception;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.domain.util.sdjwt.Disclosure;
import es.in2.issuer.backend.shared.domain.util.sdjwt.SdJwtPayloadBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl.minvws.encoding.Base45;
import org.apache.commons.compress.compressors.CompressorOutputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialSignerWorkflowImpl implements CredentialSignerWorkflow {

    private final ObjectMapper objectMapper;
    private final SigningProvider signingProvider;
    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final SdJwtPayloadBuilder sdJwtPayloadBuilder;

    @Observed(name = "issuance.sign-credential", contextualName = "issuance-sign-credential")
    @Override
    public Mono<String> signCredential(String token, String enrichedDataSet, String credentialType,
                                       String format, Map<String, Object> cnf, String issuanceId, String email) {
        log.debug("signCredential issuanceId={} format={}", issuanceId, format);

        CredentialProfile profile = credentialProfileRegistry.getByCredentialType(credentialType);
        if (profile == null) {
            log.error("Unsupported credential type: {}", credentialType);
            return Mono.error(new IllegalArgumentException("Unsupported credential type: " + credentialType));
        }

        Map<String, Object> cnfMap = cnf != null ? cnf : Map.of();

        // SD-JWT path
        if (DC_SD_JWT.equals(format) && profile.sdJwt() != null) {
            return buildSdJwtCredential(profile, enrichedDataSet, cnfMap, token, issuanceId, email);
        }

        return genericCredentialBuilder.buildJwtPayload(
                        profile, enrichedDataSet, profile.cnfRequired() ? cnfMap : null)
                .flatMap(unsignedCredential ->
                        signCredentialOnRequestedFormat(unsignedCredential, format, token, issuanceId, email)
                );
    }

    private Mono<String> signCredentialOnRequestedFormat(String unsignedCredential, String format, String token, String issuanceId, String email) {
        return Mono.defer(() -> {
            if (format.equals(JWT_VC_JSON)) {
                return setSubIfCredentialSubjectIdPresent(unsignedCredential)
                        .flatMap(payloadToSign -> {
                            log.info("Signing credential in JADES remotely ...");
                            SigningRequest signingRequest = SigningRequest.builder()
                                    .type(SigningType.JADES)
                                    .data(payloadToSign)
                                    .context(new SigningContext(token, issuanceId, email))
                                    .build();

                            return signingProvider.sign(signingRequest)
                                    .map(SigningResult::data);
                        });

            } else if (format.equals(CWT_VC)) {
                return generateCborFromJson(unsignedCredential)
                        .flatMap(cbor -> generateCOSEBytesFromCBOR(cbor, token, email, issuanceId))
                        .flatMap(this::compressAndConvertToBase45FromCOSE);
            } else {
                return Mono.error(new IllegalArgumentException("Unsupported credential format: " + format));
            }
        });
    }

    private Mono<String> setSubIfCredentialSubjectIdPresent(String unsignedCredential) {
        return Mono.fromCallable(() -> {
            JsonNode root = objectMapper.readTree(unsignedCredential);
            if (!(root instanceof ObjectNode rootObj)) {
                return unsignedCredential;
            }

            String subjectDid = extractSubjectDid(rootObj);

            if (subjectDid != null && !subjectDid.isBlank()) {
                rootObj.put("sub", subjectDid);
                return objectMapper.writeValueAsString(rootObj);
            }

            return unsignedCredential;
        })
        .subscribeOn(Schedulers.boundedElastic())
        .onErrorResume(e -> {
            log.warn(
                    "Could not set 'sub' from vc.credentialSubject.id. Keeping original payload. Reason: {}",
                    e.getMessage()
            );
            return Mono.just(unsignedCredential);
        });
    }

    private String extractSubjectDid(ObjectNode rootObj) {
        JsonNode csNode = rootObj.path("vc").path("credentialSubject");

        if (csNode.isObject()) {
            return extractIdFromObject(csNode);
        }

        if (csNode.isArray()) {
            return extractIdFromArray((ArrayNode) csNode);
        }

        return null;
    }

    private String extractIdFromObject(JsonNode csNode) {
        JsonNode idNode = csNode.path("id");
        return idNode.isTextual() ? idNode.asText() : null;
    }

    private String extractIdFromArray(ArrayNode arrayNode) {
        for (JsonNode item : arrayNode) {
            if (item != null && item.isObject()) {
                JsonNode idNode = item.path("id");
                if (idNode.isTextual() && !idNode.asText().isBlank()) {
                    return idNode.asText();
                }
            }
        }
        return null;
    }

    private Mono<byte[]> generateCborFromJson(String edgcJson) {
        return Mono.fromCallable(() -> CBORObject.FromJSONString(edgcJson).EncodeToBytes());
    }

    private Mono<byte[]> generateCOSEBytesFromCBOR(byte[] cbor, String token, String email, String issuanceId) {
        log.info("Signing credential in COSE format remotely ...");
        String cborBase64 = Base64.getEncoder().encodeToString(cbor);
        SigningRequest signingRequest = SigningRequest.builder()
                .type(SigningType.COSE)
                .data(cborBase64)
                .context(new SigningContext(token, issuanceId, email))
                .build();
        return signingProvider.sign(signingRequest)
                .map(SigningResult::data)
                .map(Base64.getDecoder()::decode);
    }

    private Mono<String> compressAndConvertToBase45FromCOSE(byte[] cose) {
        return Mono.fromCallable(() -> {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            try (CompressorOutputStream deflateOut = new CompressorStreamFactory()
                    .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, stream)) {
                deflateOut.write(cose);
            }
            byte[] zip = stream.toByteArray();
            return Base45.getEncoder().encodeToString(zip);
        }).onErrorResume(e -> {
            log.error("Error compressing and converting to Base45: " + e.getMessage(), e);
            return Mono.error(new Base45Exception("Error compressing and converting to Base45"));
        });
    }

    private Mono<String> buildSdJwtCredential(CredentialProfile profile, String decodedCredentialJson,
            Map<String, Object> cnfMap, String token, String issuanceId, String email) {
        return Mono.fromCallable(() -> sdJwtPayloadBuilder.build(decodedCredentialJson, profile, cnfMap))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(components -> {
                    log.info("Signing SD-JWT credential for issuanceId={}", issuanceId);
                    SigningRequest signingRequest = SigningRequest.builder()
                            .type(SigningType.JADES)
                            .data(components.payloadJson())
                            .context(new SigningContext(token, issuanceId, email))
                            .typ(DC_SD_JWT)
                            .build();
                    return signingProvider.sign(signingRequest)
                            .map(result -> {
                                StringBuilder sb = new StringBuilder(result.data());
                                for (Disclosure d : components.disclosures()) {
                                    sb.append('~').append(d.encoded());
                                }
                                sb.append('~');
                                return sb.toString();
                            });
                });
    }

}
