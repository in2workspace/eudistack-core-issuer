package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.ActiveCredentialOffer;
import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_CODE_SIZE;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_INPUT_MODE;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_CREDENTIAL_OFFER_PATH;
import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;
import static es.in2.issuer.backend.shared.infrastructure.util.HttpUtils.ensureUrlHasProtocol;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferServiceImpl implements CredentialOfferService {

    private static final String GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    /** Sentinel for "no email failure", so the reactive chain carries a value rather than a null. */
    private static final String NO_EMAIL_ERROR = "";

    private final PreAuthorizedCodeService preAuthorizedCodeService;
    private final TransientStore<String> issuerStateCacheStore;
    private final TransientStore<ActiveCredentialOffer> activeCredentialOfferCacheStore;
    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final EmailService emailService;
    private final IssuanceService issuanceService;
    private final TenantConfigService tenantConfigService;

    @Override
    @Observed(name = "oidc4vci.create-and-deliver-credential-offer", contextualName = "create-and-deliver-credential-offer")
    public Mono<CredentialOfferResult> createAndDeliverCredentialOffer(
            String issuanceId, String credentialConfigurationId, String grantType,
            String email, String delivery, String credentialOfferRefreshToken,
            String publicIssuerBaseUrl) {

        log.info("Delivering credential offer for issuance={} delivery={}", issuanceId, delivery);

        return generateGrant(issuanceId, grantType)
                .flatMap(grantResult -> {
                    CredentialOffer offer = CredentialOffer.builder()
                            .credentialIssuer(publicIssuerBaseUrl)
                            .credentialConfigurationIds(List.of(credentialConfigurationId))
                            .grants(grantResult.grants)
                            .build();

                    CredentialOfferData data = CredentialOfferData.builder()
                            .credentialOffer(offer)
                            .credentialEmail(email)
                            .txCode(grantResult.txCode)
                            .build();

                    return credentialOfferCacheRepository.saveCredentialOffer(data)
                            .map(nonce -> new ActiveCredentialOffer(
                                    nonce, grantResult.preAuthorizedCode, grantResult.issuerState));
                })
                .flatMap(newOffer -> {
                    AtomicBoolean settled = new AtomicBoolean(false);
                    return buildCredentialOfferUri(publicIssuerBaseUrl, newOffer.nonce())
                            .flatMap(uri -> deliverOffer(uri, issuanceId, credentialOfferRefreshToken, delivery))
                            .flatMap(result -> settleOffer(issuanceId, newOffer, result, settled).thenReturn(result))
                            .onErrorResume(ex -> invalidate(newOffer).then(Mono.error(ex)))
                            .doOnCancel(() -> discardIfUnsettled(issuanceId, newOffer, settled));
                });
    }

    /**
     * The request was cancelled (the client went away) before the new offer became the current
     * one: nobody tracks it, so no later renewal could void it. It is voided now, and the previous
     * offer stays the current one (EUD-295 review N1). Once settled, it is left alone: it may
     * already have reached the holder.
     */
    private void discardIfUnsettled(String issuanceId, ActiveCredentialOffer newOffer, AtomicBoolean settled) {
        if (settled.get()) {
            return;
        }
        log.info("Credential offer delivery for issuance={} was cancelled; discarding the new offer", issuanceId);
        invalidate(newOffer).subscribe(null, ex -> log.warn(
                "Could not discard the cancelled credential offer for issuance={}: {}", issuanceId, ex.toString()));
    }

    /**
     * One issuance has one usable offer (EUD-295). An offer that reached the holder through at
     * least one channel becomes the current one and retires the previous offer with its grant; an
     * offer that reached nobody is retired itself, so a failed renewal leaves the previous one usable.
     * A URI returned while the email failed counts as delivered: that is the issuance with
     * {@code email,ui} whose email bounced (FR-11), and its URI must keep working.
     */
    private Mono<Void> settleOffer(String issuanceId, ActiveCredentialOffer newOffer, CredentialOfferResult result,
                                   AtomicBoolean settled) {
        boolean delivered = result.credentialOfferUri() != null || result.emailError() == null;
        if (!delivered) {
            log.info("Credential offer for issuance={} was not delivered; discarding it", issuanceId);
            return invalidate(newOffer);
        }
        return activeCredentialOfferCacheStore.replace(issuanceId, newOffer)
                .doOnTerminate(() -> settled.set(true))
                .doOnNext(previous -> log.info("Retiring previous credential offer for issuance={}", issuanceId))
                .flatMap(this::invalidate);
    }

    private Mono<Void> invalidate(ActiveCredentialOffer offer) {
        Mono<Void> grant;
        if (offer.preAuthorizedCode() != null) {
            grant = preAuthorizedCodeService.revokePreAuthorizedCode(offer.preAuthorizedCode());
        } else if (offer.issuerState() != null) {
            grant = issuerStateCacheStore.delete(offer.issuerState());
        } else {
            grant = Mono.empty();
        }
        return Mono.when(credentialOfferCacheRepository.invalidateCredentialOffer(offer.nonce()), grant);
    }

    private Mono<CredentialOfferResult> deliverOffer(String credentialOfferUri, String issuanceId,
                                                     String credentialOfferRefreshToken, String delivery) {
        Set<DeliveryMode> modes = DeliveryMode.parse(delivery);

        boolean includeUri = modes.stream().anyMatch(mode -> mode.returnsUri);
        boolean sendEmail = modes.contains(DeliveryMode.EMAIL);

        log.info("Delivering credential offer for issuance={} — sendEmail={}, includeUri={}",
                issuanceId, sendEmail, includeUri);

        // The onErrorMap below wraps the whole lookup-and-send chain, not just the send (code-review
        // F3b): findCredentialOfferEmailInfoByIssuanceId can fail too (e.g. a repository error whose
        // message names a table/column/schema -- and the schema name is the tenant), and that failure
        // used to reach describeEmailFailure() raw, bypassing the safe constant below entirely.
        Mono<Void> emailTask = sendEmail
                ? issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId)
                        .flatMap(emailInfo -> buildRefreshUrl(credentialOfferRefreshToken)
                                // The standard offer goes to the email as is: turning it into a link to
                                // the tenant's wallet is the email's job, not this service's (EUD-305).
                                .flatMap(refreshUrl -> Mono.deferContextual(ctx -> {
                                    String tenantDomain = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
                                    return tenantDomain.contains("kpmg")
                                            ? sendBrandedCredentialOfferEmail(credentialOfferUri, refreshUrl, emailInfo)
                                            : sendLegacyCredentialOfferEmail(credentialOfferUri, refreshUrl, emailInfo);
                                }))
                                .doOnSuccess(v -> log.info("Credential offer email sent for issuanceId={}", issuanceId)))
                        .doOnError(ex -> log.error("Email delivery failed for issuanceId={}: {}",
                                issuanceId, ex.getMessage(), ex))
                        .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                : Mono.empty();

        // The standard OID4VCI form, unconverted (EUD-305): the client presents it, so the client
        // decides whether it becomes a QR, a link to its own wallet or a same-device hand-off.
        String uri = includeUri ? credentialOfferUri : null;

        // The email failure is reported, not propagated (FR-11): propagating it discarded a URI that
        // was already built, so a bounced email took the QR channel of the same offer down with it.
        return emailTask
                .then(Mono.just(NO_EMAIL_ERROR))
                .onErrorResume(ex -> Mono.just(describeEmailFailure(ex)))
                .map(emailError -> CredentialOfferResult.builder()
                        .credentialOfferUri(uri)
                        .emailError(NO_EMAIL_ERROR.equals(emailError) ? null : emailError)
                        .build());
    }

    private String describeEmailFailure(Throwable ex) {
        String message = ex.getMessage();
        return (message == null || message.isBlank()) ? ex.getClass().getSimpleName() : message;
    }

    private Mono<Void> sendLegacyCredentialOfferEmail(String credentialOfferUri, String refreshUrl,
                                                      CredentialOfferEmailNotificationInfo emailInfo) {
        return emailService.sendCredentialOfferEmail(
                emailInfo.email(),
                credentialOfferUri,
                refreshUrl,
                emailInfo.organization(),
                null
        );
    }

    private Mono<Void> sendBrandedCredentialOfferEmail(String credentialOfferUri, String refreshUrl,
                                                       CredentialOfferEmailNotificationInfo emailInfo) {
        return emailService.sendBrandedCredentialOfferEmail(
                emailInfo.email(),
                CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                credentialOfferUri,
                refreshUrl,
                emailInfo.organization()
        );
    }

    private Mono<String> buildRefreshUrl(String credentialOfferRefreshToken) {
        return tenantConfigService.getStringOrThrow("issuer.frontend_url")
                .map(frontendUrl -> frontendUrl + "/credential-offer-refresh/" + credentialOfferRefreshToken);
    }

    private record GrantResult(CredentialOfferGrants grants, String txCode,
                               String preAuthorizedCode, String issuerState) {}

    private Mono<GrantResult> generateGrant(String issuanceId, String grantType) {
        if (GRANT_TYPE_PRE_AUTHORIZED_CODE.equals(grantType)) {
            return generatePreAuthorizedCodeGrant(issuanceId);
        }
        return generateAuthorizationCodeGrant(issuanceId);
    }

    private Mono<GrantResult> generatePreAuthorizedCodeGrant(String issuanceId) {
        return preAuthorizedCodeService.issuePreAuthorizedCode("issuance", Mono.just(issuanceId))
                .map(preAuthResponse -> {
                    PreAuthorizedCodeGrant preAuthGrant = PreAuthorizedCodeGrant.builder()
                            .preAuthorizedCode(preAuthResponse.preAuthorizedCode())
                            .txCode(TxCode.builder()
                                    .length(TX_CODE_SIZE)
                                    .inputMode(TX_INPUT_MODE)
                                    .description("Enter the activation code")
                                    .build())
                            .build();

                    CredentialOfferGrants grants = CredentialOfferGrants.builder()
                            .preAuthorizedCode(preAuthGrant)
                            .build();

                    return new GrantResult(grants, preAuthResponse.txCodeValue(),
                            preAuthResponse.preAuthorizedCode(), null);
                });
    }

    private Mono<GrantResult> generateAuthorizationCodeGrant(String issuanceId) {
        return generateCustomNonce()
                .flatMap(issuerState -> issuerStateCacheStore.add(issuerState, issuanceId)
                        .thenReturn(issuerState))
                .map(issuerState -> {
                    AuthorizationCodeGrant authCodeGrant = AuthorizationCodeGrant.builder()
                            .issuerState(issuerState)
                            .build();

                    CredentialOfferGrants grants = CredentialOfferGrants.builder()
                            .authorizationCode(authCodeGrant)
                            .build();

                    return new GrantResult(grants, null, null, issuerState);
                });
    }

    private Mono<String> buildCredentialOfferUri(String baseUrl, String nonce) {
        String rawIssuerOfferUrl = ensureUrlHasProtocol(baseUrl + OID4VCI_CREDENTIAL_OFFER_PATH + "/" + nonce);
        String encodedRawUrl = URLEncoder.encode(rawIssuerOfferUrl, StandardCharsets.UTF_8);

        String finalUri = CREDENTIAL_OFFER_PREFIX + encodedRawUrl;
        log.info("BUILDING URI - Result: {}", finalUri);

        return Mono.just(finalUri);
    }
}