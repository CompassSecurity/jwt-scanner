package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.JwtScannerExtension;

import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class CheckExpiredJwtAccepted extends Check {

    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    @Override
    public Optional<AuditIssue> perform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        if (jwt.isExpired()) {
            return perform(baseRequestResponse, auditInsertionPoint, "expired jwt", jwt, JwtAuditIssues::expiredAccepted);
        } else {
            // Schedule a recheck.
            jwt.getExp().ifPresent(exp -> {
                var now = System.currentTimeMillis() / 1000;
                var left = exp.longValue() - now;
                executor.schedule(
                        () -> new CheckExpiredJwtAccepted().perform(baseRequestResponse, auditInsertionPoint).ifPresent(JwtScannerExtension.api().siteMap()::add),
                        left + 60, TimeUnit.SECONDS);
            });
            return Optional.empty();
        }
    }

}
