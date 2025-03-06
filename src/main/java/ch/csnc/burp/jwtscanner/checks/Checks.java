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

    // TODO add check for jku ping back
    public static void performAll(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, Consumer<AuditIssue> auditIssueConsumer) {
        new CheckJwtExists().perform(baseRequestResponse, auditInsertionPoint).ifPresent(jwtExistsIssue -> {
            auditIssueConsumer.accept(jwtExistsIssue);
            // Further checks only make sense if the JWT exists.
            new CheckAlg().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            new CheckJwtHasExpiry().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            new CheckJwtExpired().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            new CheckExpiredJwtAccepted().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            new CheckWithoutSignature().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            new CheckInvalidSignature().perform(baseRequestResponse, auditInsertionPoint).ifPresentOrElse(auditIssueConsumer, () -> {
                // If a JWT is accepted with an invalid signature, further attacks, such as algorithm confusion attacks,
                // should not be attempted, as they will succeed regardless. Thus this block is only executed, if a JWT with
                // invalid signature is not accepted.
                new CheckAlgNone().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckEmptyPassword().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckKidHeaderPathTraversal().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckInvalidEcdsa().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckJwkHeaderInjection().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckJkuPingback().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckJkuHeaderInjection().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                new CheckJwks().perform(baseRequestResponse, auditInsertionPoint).ifPresentOrElse(jwksDetectedIssue -> {
                    auditIssueConsumer.accept(jwksDetectedIssue);
                    new CheckAlgConfusionExposedPublicKey().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                }, () -> {
                    // If no public key is exposed, it should be checked whether a forged public key can be used.
                    new CheckAlgConfusionForgedPublicKey().perform(baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                });
            });
        });
    }

}
