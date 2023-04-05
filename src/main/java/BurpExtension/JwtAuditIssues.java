package BurpExtension;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public abstract class JwtAuditIssues {
    public static final AuditIssue getAlgNone(String url, HttpRequestResponse checkRequestResponse){
         return auditIssue("Algorithm none JWT attack",
                "Some JWT issue was found: ",
                "Validate the JWT correctly!",
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
