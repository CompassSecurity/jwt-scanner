package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.JwtParseException;

import java.util.Optional;

/**
 * Performs the audit check to determine if a JWT is present in the specified insertion point.
 * <p>
 * If a valid JWT is detected, an {@link AuditIssue} is created with {@link AuditIssueConfidence#FIRM} confidence.
 * If the value at the insertion point is not a valid JWT, the exception is swallowed
 * to prevent log pollution, and an empty Optional is returned.
 */
public class CheckJwtExists extends Check {

    @Override
    protected Optional<AuditIssue> doPerform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        try {
            var jwt = new Jwt(auditInsertionPoint.baseValue());
            var markers = markersOf(baseRequestResponse, auditInsertionPoint);
            var auditIssue = JwtAuditIssues.jwtDetected(jwt, AuditIssueConfidence.FIRM, baseRequestResponse.withRequestMarkers(markers));
            return Optional.of(auditIssue);
        } catch (JwtParseException exc) {
            // Silent catch to avoid log pollution.
            return Optional.empty();
        }
    }

}
