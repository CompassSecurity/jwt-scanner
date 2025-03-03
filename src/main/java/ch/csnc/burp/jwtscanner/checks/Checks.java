package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.function.Consumer;

/**
 * New {@link Check checks} should be added here. {@link Check Checks} defined here are executed either by
 * {@link ch.csnc.burp.jwtscanner.ContextMenu ContextMenu} or {@link ch.csnc.burp.jwtscanner.JwtScanCheck JwtScanCheck}
 */
public abstract class Checks {

    public static void performAll(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, Consumer<AuditIssue> auditIssueConsumer) {
        new CheckJwtExists().check(baseRequestResponse, auditInsertionPoint).ifPresent(jwtExistsIssue -> {
            auditIssueConsumer.accept(jwtExistsIssue);
            // Further checks only make sense if the JWT exists.
            new CheckAlg().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            new CheckJwks().check(baseRequestResponse, auditInsertionPoint).ifPresent(jwksDetectedIssue -> {
                auditIssueConsumer.accept(jwksDetectedIssue);
                new CheckAlgConfusion().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            });
            new CheckJwtExpired().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            new CheckExpiredJwtAccepted().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            new CheckWithoutSignature().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            new CheckInvalidSignature().check(baseRequestResponse, auditInsertionPoint).ifPresentOrElse(auditIssueConsumer, () -> {
                // If a JWT is accepted with an invalid signature, further attacks, such as algorithm confusion attacks,
                // should not be attempted, as they will succeed regardless. Thus this block is only executed, if a JWT with
                // invalid signature is not accepted.
                new CheckAlgNone().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckEmptyPassword().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckKidHeaderPathTraversal().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckInvalidEcdsa().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckJwkHeaderInjection().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckJkuHeaderInjection().check(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            });
        });
    }

}
