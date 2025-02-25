package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;

import java.util.Optional;

/**
 * This is an informational check. It determines whether the algorithm used is symmetric or asymmetric.
 */
public class CheckAlg extends Check {

    @Override
    public Optional<AuditIssue> check(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        if (jwt.hasSymmetricAlg()) {
            return Optional.of(JwtAuditIssues.hasSymmetricAlg(jwt, AuditIssueConfidence.FIRM, baseRequestResponse));
        }
        if (jwt.hasAsymmetricAlg()) {
            return Optional.of(JwtAuditIssues.hasAsymmetricAlg(jwt, AuditIssueConfidence.FIRM, baseRequestResponse));
        }
        return Optional.of(JwtAuditIssues.unknownAlg(jwt, AuditIssueConfidence.FIRM, baseRequestResponse));
    }

}
