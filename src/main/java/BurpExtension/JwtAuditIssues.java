package BurpExtension;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public abstract class JwtAuditIssues {
    public static final AuditIssue getAlgNone(String url, HttpRequestResponse checkRequestResponse){
         return auditIssue("Algorithm none JWT attack",
                "The server accepts JWTs created with the \"none\" algorithm. \n " +
                        "The JWT ànoneà algorithm is a waz of creating a JWT without adding a signature. " +
                        "This means that the token cannot be validated, making it vulnerable to tampering and manipulation." +
                        "An attacker can leverage this to impersonate any user",
                "The server should not accept tokens that were created using the \"none\" algorithm. " +
                        "(Note that upper- and lower-case variations such as \"None\" or \"nONe\" must not be accepted either.)\n" +
                        "The server should ignore the \"alg\" header claim and instead define a fixed signature algorithm in the application code.",
                // baseRequestResponse.request().url(),
                url,
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.CERTAIN,
                null,
                null,
                AuditIssueSeverity.HIGH,
                checkRequestResponse);
    }

    public static final AuditIssue invalidSignature(String url, HttpRequestResponse checkRequestResponse){
        return auditIssue("Invalid JWT Signature",
                "The signature of the JSON Web Tokens (JWT) is not checked by the server.\n" +
                        "An attacker can forge a JWT and take over any account and role in the application. " +
                        "This can be used to elevate privileges for instance.",
                "A standard library should be used to handle the JWT in order to prevent implementation errors and vulnerabilities.\n" +
                        "There, the signature verification must be enabled.",
                // baseRequestResponse.request().url(),
                url,
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.CERTAIN,
                null,
                null,
                AuditIssueSeverity.HIGH,
                checkRequestResponse);
    }
}
