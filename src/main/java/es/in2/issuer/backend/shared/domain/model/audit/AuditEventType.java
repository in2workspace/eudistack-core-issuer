package es.in2.issuer.backend.shared.domain.model.audit;

import java.util.Optional;
import java.util.Set;

/**
 * The audit event types the Issuer produces, with the {@code action} and the {@code reason}
 * vocabulary that catalogue 2.2.0 fixes for each. The audit API rejects an event whose action differs,
 * or whose reason is outside the type's vocabulary or contradicts the result the reason determines, so
 * those rules are enforced here before an event can be built.
 */
public enum AuditEventType {

    AUTHORIZATION_DECISION("AuthorizationDecision", "Authorize", AuditSource.ISSUER,
            Set.of("PowerMissing", "OutOfScope", "TenantMismatch", "PlatformTenantReadOnly"),
            Set.of()),
    ISSUANCE_REQUESTED("IssuanceRequested", AuditVocabulary.ACTION_ISSUE, AuditSource.ISSUER,
            Set.of(), Set.of()),
    ISSUANCE_ATTEMPT_FAILED("IssuanceAttemptFailed", AuditVocabulary.ACTION_ISSUE, AuditSource.ISSUER,
            Set.of("UnknownAttestationType", "InvalidRequestData", AuditVocabulary.POLICY_DENIED, "AttributeVerificationFailed",
                    "InvalidTransactionCode", "InvalidProofOfPossession"),
            Set.of("AttributeSourceUnavailable", AuditVocabulary.SIGNING_FAILED, AuditVocabulary.STATUS_LIST_UNAVAILABLE, "InvalidConfiguration")),
    CREDENTIAL_OFFER_SENT("CredentialOfferSent", "SendOffer", AuditSource.ISSUER,
            Set.of(), Set.of("MailDeliveryFailed")),
    ISSUANCE_COMPLETED("IssuanceCompleted", AuditVocabulary.ACTION_ISSUE, AuditSource.ISSUER,
            Set.of(), Set.of()),
    WALLET_NOTIFICATION_RECEIVED("WalletNotificationReceived", "ReceiveNotification", AuditSource.ISSUER,
            Set.of(), Set.of()),
    REVOCATION("Revocation", "Revoke", AuditSource.ISSUER,
            Set.of(AuditVocabulary.POLICY_DENIED, "IssuanceNotFound", "AlreadyRevoked", "NotRevocable"),
            Set.of(AuditVocabulary.STATUS_LIST_UNAVAILABLE)),
    ISSUANCE_WITHDRAWN("IssuanceWithdrawn", "Withdraw", AuditSource.ISSUER,
            Set.of(AuditVocabulary.POLICY_DENIED, "InvalidStatus"), Set.of()),
    ISSUANCE_ARCHIVED("IssuanceArchived", "Archive", AuditSource.ISSUER,
            Set.of(AuditVocabulary.POLICY_DENIED, "InvalidStatus"), Set.of()),
    ISSUANCE_QUERIED("IssuanceQueried", "QueryIssuances", AuditSource.ISSUER,
            Set.of(AuditVocabulary.POLICY_DENIED, "UnknownIdentifierType"), Set.of()),
    ISSUANCE_DETAIL_ACCESSED("IssuanceDetailAccessed", "ReadIssuance", AuditSource.ISSUER,
            Set.of(AuditVocabulary.POLICY_DENIED, "IssuanceNotFound"), Set.of()),
    CATALOG_ENTRY_CHANGED("CatalogEntryChanged", "ConfigureCatalog", AuditSource.ISSUER,
            Set.of(AuditVocabulary.POLICY_DENIED, "InvalidConfiguration"), Set.of()),
    EXTERNAL_SYSTEM_ACCESS("ExternalSystemAccess", "AccessExternalSystem", AuditSource.ISSUER,
            Set.of("AuthenticationRejected", "SourceNotTrusted"),
            Set.of("ErrorResponse", "InvalidResponse", "Timeout", "Unreachable")),
    STATUS_LIST_CREATED("StatusListCreated", "CreateStatusList", AuditSource.STATUS_LISTS,
            Set.of(), Set.of(AuditVocabulary.SIGNING_FAILED)),
    STATUS_ENTRY_CHANGED("StatusEntryChanged", "ChangeStatusEntry", AuditSource.STATUS_LISTS,
            Set.of(), Set.of("ListFull", AuditVocabulary.STATUS_LIST_UNAVAILABLE)),
    STATUS_LIST_PUBLISHED("StatusListPublished", "PublishStatusList", AuditSource.STATUS_LISTS,
            Set.of(), Set.of(AuditVocabulary.SIGNING_FAILED, "PublicationFailed")),
    SIGNATURE_REQUESTED("SignatureRequested", "Sign", AuditSource.SIGNING,
            Set.of(),
            Set.of("NoActiveConfiguration", "UnsupportedAlgorithm", "CredentialsRejected", "ProviderUnavailable",
                    "InvalidSignatureResponse"));

    private final String catalogName;
    private final String action;
    private final String defaultSource;
    private final Set<String> deniedReasons;
    private final Set<String> failureReasons;

    AuditEventType(String catalogName, String action, String defaultSource,
                   Set<String> deniedReasons, Set<String> failureReasons) {
        this.catalogName = catalogName;
        this.action = action;
        this.defaultSource = defaultSource;
        this.deniedReasons = deniedReasons;
        this.failureReasons = failureReasons;
    }

    public String catalogName() {
        return catalogName;
    }

    public String action() {
        return action;
    }

    public String defaultSource() {
        return defaultSource;
    }

    /** The result a reason determines for this type, or empty when the reason is outside its vocabulary. */
    public Optional<AuditResult> resultFor(String reason) {
        if (deniedReasons.contains(reason)) {
            return Optional.of(AuditResult.DENIED);
        }
        if (failureReasons.contains(reason)) {
            return Optional.of(AuditResult.FAILURE);
        }
        return Optional.empty();
    }
}
