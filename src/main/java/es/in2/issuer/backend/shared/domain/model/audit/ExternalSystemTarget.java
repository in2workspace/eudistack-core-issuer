package es.in2.issuer.backend.shared.domain.model.audit;

/**
 * A third-party system the Issuer calls, as the {@code ExternalSystemAccess} event describes it.
 *
 * @param systemType           catalogue {@code system_type}
 * @param system               registered name or host of the third party
 * @param authenticationMethod catalogue {@code authentication_method}
 * @param source               the module that makes the call, which is the producer of the event
 */
public record ExternalSystemTarget(String systemType, String system, String authenticationMethod, String source) {

    public static final String SYSTEM_TYPE_MAIL_PROVIDER = "MailProvider";
    public static final String SYSTEM_TYPE_QTSP = "Qtsp";

    public static final String AUTHENTICATION_NONE = "None";
    public static final String AUTHENTICATION_BASIC = "Basic";
    public static final String AUTHENTICATION_API_KEY = "ApiKey";
    public static final String AUTHENTICATION_OAUTH_CLIENT_CREDENTIALS = "OAuthClientCredentials";

    public static ExternalSystemTarget mailProvider(String system, String authenticationMethod) {
        return new ExternalSystemTarget(SYSTEM_TYPE_MAIL_PROVIDER, system, authenticationMethod, AuditSource.ISSUER);
    }

    public static ExternalSystemTarget qtsp(String system, String authenticationMethod) {
        return new ExternalSystemTarget(SYSTEM_TYPE_QTSP, system, authenticationMethod, AuditSource.SIGNING);
    }
}
