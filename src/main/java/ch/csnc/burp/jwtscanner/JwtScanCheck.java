package ch.csnc.burp.jwtscanner;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import ch.csnc.burp.jwtscanner.checks.Checks;

import java.util.ArrayList;

import static burp.api.montoya.scanner.AuditResult.auditResult;

public class JwtScanCheck implements ActiveScanCheck {

    @Override
    public String checkName() {
        return "JWT Scanner";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, Http http) {
        var auditIssues = new ArrayList<AuditIssue>();
        Checks.performAll(baseRequestResponse, auditInsertionPoint, auditIssues::add);
        return auditResult(auditIssues);
    }

}
