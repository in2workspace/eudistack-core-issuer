package es.in2.issuer.backend.signing.infrastructure.s3;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

/**
 * Matches when {@code issuer.signing.certificates.arn} ({@code S3_CERTIFICATE_ARN}) has text. Not
 * {@code @ConditionalOnProperty}: application.yml maps the variable with an empty default, and an empty value
 * would still match it. Not {@code @ConditionalOnExpression} either: the placeholder would be pasted into the
 * expression and evaluated, so a crafted value of the variable could run code at startup.
 */
class OwnKeyCertificatesConfigured implements Condition {

    static final String ARN_PROPERTY = "issuer.signing.certificates.arn";

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        return StringUtils.hasText(context.getEnvironment().getProperty(ARN_PROPERTY));
    }
}
