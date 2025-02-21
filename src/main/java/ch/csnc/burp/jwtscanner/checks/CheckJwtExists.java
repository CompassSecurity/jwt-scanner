package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;

import java.util.Optional;

/**
 * This check is not truly a check.
 * Upon entering the {@link } method, we already have a valid insertion point and know that a JWT exists.
 * What this check does additionally is create the corresponding AuditIssue.
 */
public class CheckJwtExists extends Check {

    @Override
    public Optional<AuditIssue> check(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var markers = markersOf(baseRequestResponse, auditInsertionPoint);
        var auditIssue = JwtAuditIssues.jwtDetected(AuditIssueConfidence.FIRM, baseRequestResponse.withRequestMarkers(markers));
        return Optional.of(auditIssue);
    }

}
