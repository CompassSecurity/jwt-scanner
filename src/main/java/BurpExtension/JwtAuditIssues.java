package BurpExtension;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public abstract class JwtAuditIssues {

    public static AuditIssue expired(HttpRequestResponse baseRequestResponse, HttpRequestResponse markedRequestResponse){
        return auditIssue("Expired JWT accepted",
                "The server accepts JWTs that are expired \n " +
                        "An attacker can use an expired JWT.",
                "A standard library should be used to handle the JWT in order to prevent " +
                        "implementation errors and vulnerabilities.\n" +
                        "There, the signature verification must be enabled.",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                null,
                null,
                AuditIssueSeverity.HIGH,
                markedRequestResponse);
    }

    public static AuditIssue withoutSignature(HttpRequestResponse baseRequestResponse, HttpRequestResponse markedRequestResponse){
        return auditIssue("JWT Signature not required",
                "The server accepts JWTs that are not signed \n " +
                        "An attacker can forge a JWT and take over any account and role in the application. " +
                        "This can be used to elevate privileges for instance.",
                "The server should not accept any expired JWTs.",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                null,
                null,
                AuditIssueSeverity.HIGH,
                markedRequestResponse);
    }

    public static AuditIssue getAlgNone(HttpRequestResponse baseRequestResponse, HttpRequestResponse markedRequestResponse){
         return auditIssue("Algorithm none JWT attack",
                "The server accepts JWTs created with the \"none\" algorithm. \n " +
                        "The JWT ànoneà algorithm is a waz of creating a JWT without adding a signature. " +
                        "This means that the token cannot be validated, making it vulnerable to tampering and manipulation." +
                        "An attacker can leverage this to impersonate any user",
                "The server should not accept tokens that were created using the \"none\" algorithm. " +
                        "(Note that upper- and lower-case variations such as \"None\" or \"nONe\" must not be accepted either.)\n" +
                        "The server should ignore the \"alg\" header claim and instead define a fixed signature algorithm in the application code.",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                null,
                null,
                AuditIssueSeverity.HIGH,
                markedRequestResponse);
    }

    public static AuditIssue invalidSignature(HttpRequestResponse baseRequestResponse, HttpRequestResponse markedRequestResponse){
        return auditIssue("Invalid JWT Signature",
                "The signature of the JSON Web Tokens (JWT) is not checked by the server.\n" +
                        "An attacker can forge a JWT and take over any account and role in the application. " +
                        "This can be used to elevate privileges for instance.",
                "A standard library should be used to handle the JWT in order to prevent implementation errors and vulnerabilities.\n" +
                        "There, the signature verification must be enabled.",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                null,
                null,
                AuditIssueSeverity.HIGH,
                markedRequestResponse);
    }

    public static AuditIssue emptyPassword(HttpRequestResponse baseRequestResponse, HttpRequestResponse markedRequestResponse){
        return auditIssue("JWT signed with empty password",
                "The signature of the JSON Web Tokens (JWT) is created with an empty password.\n" +
                        "An attacker can forge a JWT with an empty password and take over any account and role in the application. " +
                        "This can be used to elevate privileges for instance.",
                "A standard library should be used to handle the JWT in order to prevent implementation errors and vulnerabilities.\n" +
                        "No Empty secrets should be used to create signatures.\n"+
                        "The signature verification must be enabled.",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                null,
                null,
                AuditIssueSeverity.HIGH,
                markedRequestResponse);
    }
    public static AuditIssue invalidEcdsa(HttpRequestResponse baseRequestResponse, HttpRequestResponse markedRequestResponse){
        return auditIssue("JWT signed invalid ECDSA parameters",
                "CVE-2022-21449 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE.\n" +
                        "Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE," +
                        " Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, " +
                        "deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data.",
                "Install available patch and refer to vendor advisory: https://www.oracle.com/security-alerts/cpuapr2022.html",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                null,
                null,
                AuditIssueSeverity.HIGH,
                markedRequestResponse);
    }
    public static AuditIssue jwksInjection(HttpRequestResponse baseRequestResponse, HttpRequestResponse markedRequestResponse){
        return auditIssue("JWT JWKs Injection",
                "It is possible to include the used public key in the JWK value of the header. The Application takes the included public key to validate the signature",
                "The JWK provided in the header should not be used to validate the signature.",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                null,
                null,
                AuditIssueSeverity.HIGH,
                markedRequestResponse);
    }

}
