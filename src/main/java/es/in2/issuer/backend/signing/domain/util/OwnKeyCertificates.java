package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.signing.domain.exception.CertificateCheckException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.CertificateCheck;

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The own-key certificate as infra publishes it: a PEM chain, leaf first, root excluded. From the leaf
 * come the organization the certificate belongs to and the name of the KMS key that signs with it.
 */
public final class OwnKeyCertificates {

    /** Prefix of every own-key alias; the runtime role of the Issuer is meant to sign only with these aliases. */
    public static final String ALIAS_PREFIX = "alias/own-key-";

    private static final String ORGANIZATION_IDENTIFIER_OID = "2.5.4.97";
    private static final String ORGANIZATION_IDENTIFIER = "organizationIdentifier";

    private OwnKeyCertificates() {}

    /**
     * @return the certificates of the chain, in the order of the PEM
     * @throws SigningException {@code CERTIFICATE_INVALID} if the PEM holds no certificate or cannot be parsed
     */
    public static List<X509Certificate> parsePemChain(String pem) {
        try {
            var certificates = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate certificate : certificates) {
                chain.add((X509Certificate) certificate);
            }
            if (chain.isEmpty()) {
                throw invalid("The own-key certificate chain holds no certificate", null);
            }
            return List.copyOf(chain);
        } catch (GeneralSecurityException | ClassCastException e) {
            throw invalid("The own-key certificate chain cannot be parsed", e);
        }
    }

    /** The chain as the JWS {@code x5c} value: standard base64 of each DER certificate. */
    public static List<String> toX5c(List<X509Certificate> chain) {
        try {
            List<String> x5c = new ArrayList<>();
            for (X509Certificate certificate : chain) {
                x5c.add(Base64.getEncoder().encodeToString(certificate.getEncoded()));
            }
            return List.copyOf(x5c);
        } catch (CertificateEncodingException e) {
            throw invalid("The own-key certificate chain cannot be encoded", e);
        }
    }

    /**
     * The {@code organizationIdentifier} (2.5.4.97) of the subject of the certificate, and only of the
     * subject: never of its issuer nor of another certificate of the chain. It is read wherever it is in the
     * subject, also inside a multi-valued RDN.
     *
     * @throws CertificateCheckException {@code DUPLICATED_ORGANIZATION_IDENTIFIER} if the subject holds more
     *                                   than one, multi-valued RDNs included: the organization would be ambiguous
     */
    public static Optional<String> subjectOrganizationIdentifier(X509Certificate certificate) {
        // With a keyword for the OID the value is written as a string; without it, RFC 2253 writes it in hex.
        String name = certificate.getSubjectX500Principal()
                .getName(X500Principal.RFC2253, Map.of(ORGANIZATION_IDENTIFIER_OID, ORGANIZATION_IDENTIFIER));
        try {
            List<Object> values = organizationIdentifierValues(new LdapName(name).getRdns());
            if (values.size() > 1) {
                throw new CertificateCheckException(CertificateCheck.DUPLICATED_ORGANIZATION_IDENTIFIER,
                        "The subject of the own-key certificate holds more than one organizationIdentifier");
            }
            return values.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .filter(value -> !value.isBlank())
                    .findFirst();
        } catch (InvalidNameException e) {
            return Optional.empty();
        }
    }

    /** Every organizationIdentifier value of the subject, in single- and multi-valued RDNs alike. */
    private static List<Object> organizationIdentifierValues(List<Rdn> rdns) {
        List<Object> values = new ArrayList<>();
        for (Rdn rdn : rdns) {
            try {
                NamingEnumeration<? extends Attribute> attributes = rdn.toAttributes().getAll();
                while (attributes.hasMore()) {
                    Attribute attribute = attributes.next();
                    if (ORGANIZATION_IDENTIFIER.equalsIgnoreCase(attribute.getID())) {
                        for (int i = 0; i < attribute.size(); i++) {
                            values.add(attribute.get(i));
                        }
                    }
                }
            } catch (NamingException e) {
                throw new CertificateCheckException(CertificateCheck.UNPARSABLE,
                        "The subject of the own-key certificate cannot be read", e);
            }
        }
        return values;
    }

    /**
     * The alias of the KMS key of the certificate: {@value #ALIAS_PREFIX} followed by the SHA-256 of the
     * DER SubjectPublicKeyInfo of the certificate, in lowercase hexadecimal. It depends only on the key, so
     * a certificate renewed with the same key keeps its alias.
     */
    public static String keyAlias(X509Certificate certificate) {
        try {
            byte[] spkiSha256 = MessageDigest.getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded());
            return ALIAS_PREFIX + HexFormat.of().formatHex(spkiSha256);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("The JDK does not provide SHA-256", e);
        }
    }

    private static SigningException invalid(String message, Throwable cause) {
        return new CertificateCheckException(CertificateCheck.UNPARSABLE, message, cause);
    }
}
