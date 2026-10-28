package es.in2.issuer.backend.signing.domain.spi;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.Set;

/**
 * Reads the X.509 contents that the JDK does not decode (certificate policies, qcStatements and the
 * {@code organizationIdentifier} of the subject), so that the domain does not depend on an ASN.1 library.
 */
public interface CertificateExtensionsPort {

    /**
     * @return the policy identifiers (OIDs) of the {@code certificatePolicies} extension; empty if it has none
     * @throws RuntimeException if the extension is present but cannot be read
     */
    Set<String> policyIdentifiers(X509Certificate certificate);

    /**
     * @return the statement identifiers (OIDs) of the {@code qcStatements} extension; empty if it has none
     * @throws RuntimeException if the extension is present but cannot be read
     */
    Set<String> qcStatementIdentifiers(X509Certificate certificate);

    /** @return the first {@code organizationIdentifier} (2.5.4.97) of the subject, if any */
    Optional<String> organizationIdentifier(X509Certificate certificate);
}
