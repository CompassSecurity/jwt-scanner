package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;

import java.util.Optional;

/**
 * Checks whether the JWT has an expiration (exp claim).
 */
public class CheckJwtHasExpiry extends Check {

    @Override
    public Optional<AuditIssue> perform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        if (!jwt.hasExpiry()) {
            var markers = markersOf(baseRequestResponse, auditInsertionPoint);
            var auditIssue = JwtAuditIssues.noExpiry(jwt, AuditIssueConfidence.FIRM, baseRequestResponse.withRequestMarkers(markers));
            return Optional.of(auditIssue);
        }
        // TODO schedule for expiry
        return Optional.empty();
    }

}
