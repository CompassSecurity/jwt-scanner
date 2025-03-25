package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;

import java.util.Optional;

/**
 * Checks whether kid header path traversal is possible
 */
public class CheckKidHeaderPathTraversal extends Check {

    @Override
    public Optional<AuditIssue> perform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue()).withKidPointingToDevNull();
        return perform(baseRequestResponse, auditInsertionPoint, "kid path traversal", jwt, JwtAuditIssues::kidHeaderPathTraversal);
    }

}
