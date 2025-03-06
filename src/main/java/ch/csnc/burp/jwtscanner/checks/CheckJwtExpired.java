package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.JwtScannerExtension;

import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Checks whether the JWT is already expired.
 */
public class CheckJwtExpired extends Check {

    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    @Override
    public Optional<AuditIssue> perform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        if (jwt.isExpired()) {
            var markers = markersOf(baseRequestResponse, auditInsertionPoint);
            var auditIssue = JwtAuditIssues.expired(jwt, AuditIssueConfidence.FIRM, baseRequestResponse.withRequestMarkers(markers));
            return Optional.of(auditIssue);
        } else {
            // Schedule a check.
            jwt.getExp().ifPresent(exp -> {
                var now = System.currentTimeMillis() / 1000;
                var left = exp.longValue() - now;
                executor.schedule(
                        () -> new CheckJwtExpired().perform(baseRequestResponse, auditInsertionPoint).ifPresent(JwtScannerExtension.api().siteMap()::add),
                        left + 60, TimeUnit.SECONDS);
            });
            return Optional.empty();
        }
    }

}
