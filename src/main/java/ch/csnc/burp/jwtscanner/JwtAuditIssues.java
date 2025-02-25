package ch.csnc.burp.jwtscanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public abstract class JwtAuditIssues {

    @FunctionalInterface
    public interface JwtAuditIssue {
        AuditIssue get(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses);
    }

    @SafeVarargs
    private static <T> List<T> listOf(T element, T... elements) {
        var list = new ArrayList<T>();
        list.add(element);
        list.addAll(Arrays.asList(elements));
        return List.copyOf(list);
    }

    public static AuditIssue hasSymmetricAlg(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        var alg = jwt.getAlg();
        return auditIssue(
                "JWT is signed symmetrically",
                """
                        <p>alg: %s</p>
                        <p>
                          Try to crack it:
                          <pre>hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list</pre>
                        </p>""".formatted(alg),
                "",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.INFORMATION,
                confidence,
                null,
                null,
                AuditIssueSeverity.INFORMATION,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue hasAsymmetricAlg(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        var alg = jwt.getAlg();
        return auditIssue(
                "JWT is signed asymmetrically",
                "alg: %s".formatted(alg),
                "",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.INFORMATION,
                confidence,
                null,
                null,
                AuditIssueSeverity.INFORMATION,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue unknownAlg(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        var alg = jwt.getAlg();
        return auditIssue(
                "JWT has unknown algorithm",
                "alg: %s".formatted(alg),
                "",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue jwtDetected(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue(
                "JWT detected",
                "",
                "",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.INFORMATION,
                confidence,
                null,
                null,
                AuditIssueSeverity.INFORMATION,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue jkuDetected(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue(
                "JSON Web Key Sets detected",
                "jku: %s".formatted(jwt.getJku()),
                "",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.INFORMATION,
                confidence,
                null,
                null,
                AuditIssueSeverity.INFORMATION,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue jwksDetected(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue(
                "JSON Web Key Sets detected",
                checkRequestResponses[0].request().url(),
                "",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.INFORMATION,
                confidence,
                null,
                null,
                AuditIssueSeverity.INFORMATION,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue expired(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("JWT expired",
                "",
                "",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.INFORMATION,
                confidence,
                null,
                null,
                AuditIssueSeverity.INFORMATION,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue noExpiry(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("JWT does not expire",
                """
                        The JWT does not expire.
                        An attacker can use the JWT for an undefined period of time.""",
                """
                        Always include an expiration time in the JWT. This can be done by setting the exp claim, which
                        specifies the expiration time as a Unix timestamp. This ensures that the token is only valid for a limited period.""",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue expiredAccepted(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("Expired JWT accepted",
                """
                        The server accepts JWTs that are expired.
                        An attacker can use an expired JWT.""",
                """
                        A standard library should be used to handle the JWT in order to prevent
                        implementation errors and vulnerabilities.
                        There, the signature verification must be enabled.""",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue withoutSignature(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("JWT Signature not required",
                """
                        The server accepts JWTs that are not signed
                        An attacker can forge a JWT and take over any account and role in the application.
                        This can be used to elevate privileges for instance.""",
                "The server should not accept any expired JWTs.",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue algNone(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("Algorithm none JWT attack",
                """
                        The server accepts JWTs created with the "none" algorithm.
                        The JWT ànoneà algorithm is a waz of creating a JWT without adding a signature.
                        This means that the token cannot be validated, making it vulnerable to tampering and manipulation.
                        An attacker can leverage this to impersonate any user""",
                """
                        The server should not accept tokens that were created using the "none" algorithm.
                        (Note that upper- and lower-case variations such as "None" or "nONe" must not be accepted either.)
                        The server should ignore the "alg" header claim and instead define a fixed signature algorithm in the application code.""",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue invalidSignature(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("Invalid JWT Signature",
                """
                        The signature of the JSON Web Tokens (JWT) is not checked by the server.
                        An attacker can forge a JWT and take over any account and role in the application.
                        This can be used to elevate privileges for instance.""",
                """
                        A standard library should be used to handle the JWT in order to prevent implementation errors and vulnerabilities.
                        There, the signature verification must be enabled.""",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue emptyPassword(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("JWT signed with empty password",
                """
                        The signature of the JSON Web Tokens (JWT) is created with an empty password.
                        "An attacker can forge a JWT with an empty password and take over any account and role in the application.
                        "This can be used to elevate privileges for instance.""",
                """
                        A standard library should be used to handle the JWT in order to prevent implementation errors and vulnerabilities.
                        No Empty secrets should be used to create signatures.
                        The signature verification must be enabled.""",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue invalidEcdsa(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("JWT signed invalid ECDSA parameters",
                """
                        CVE-2022-21449 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE.
                        Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
                        Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation,
                        deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data.""",
                "Install available patch and refer to vendor advisory: https://www.oracle.com/security-alerts/cpuapr2022.html",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue jwkHeaderInjection(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("JWT jwk header injection",
                "It is possible to include the used public key in the JWK value of the header. The Application takes the included public key to validate the signature",
                "The JWK provided in the header should not be used to validate the signature.",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

    public static AuditIssue jkuHeaderInjection(Jwt jwt, AuditIssueConfidence confidence, HttpRequestResponse baseRequestResponse, HttpRequestResponse... checkRequestResponses) {
        return auditIssue("JWT jku header injection",
                "JWT JKU header injection is a vulnerability where an attacker can manipulate the jku (JSON Web Key Set URL) header to point to a malicious key set, enabling them to forge or alter JWTs.",
                "To remediate this, implement strict validation of the jku value by whitelisting trusted key sources and ensuring that any keys fetched are from secure, verified endpoints.",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                confidence,
                null,
                null,
                AuditIssueSeverity.HIGH,
                listOf(baseRequestResponse, checkRequestResponses));
    }

}
