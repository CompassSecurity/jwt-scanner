package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ch.csnc.burp.jwtscanner.JwtScannerExtension;

import java.util.Optional;
import java.util.function.Consumer;

/**
 * New {@link Check checks} should be added here. {@link Check Checks} defined here are executed either by
 * {@link ch.csnc.burp.jwtscanner.ContextMenu ContextMenu} or {@link ch.csnc.burp.jwtscanner.JwtScanCheck JwtScanCheck}
 */
public abstract class Checks {

    public static void performAll(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, Consumer<AuditIssue> auditIssueConsumer) {
        perform(new CheckJwtExists(), baseRequestResponse, auditInsertionPoint).ifPresent(jwtExistsIssue -> {
            auditIssueConsumer.accept(jwtExistsIssue);
            // Further checks only make sense if the JWT exists.
            perform(new CheckAlg(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            perform(new CheckJwtHasExpiry(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            perform(new CheckJwtExpired(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            perform(new CheckExpiredJwtAccepted(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            perform(new CheckWithoutSignature(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
            perform(new CheckInvalidSignature(), baseRequestResponse, auditInsertionPoint).ifPresentOrElse(auditIssueConsumer, () -> {
                // If a JWT is accepted with an invalid signature, further attacks, such as algorithm confusion attacks,
                // should not be attempted, as they will succeed regardless. Thus this block is only executed, if a JWT with
                // invalid signature is not accepted.
                perform(new CheckAlgNone(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                perform(new CheckEmptyPassword(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                perform(new CheckKidHeaderPathTraversal(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                perform(new CheckInvalidEcdsa(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                perform(new CheckJwkHeaderInjection(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                perform(new CheckJkuPingback(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                perform(new CheckJkuHeaderInjection(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                perform(new CheckJwks(), baseRequestResponse, auditInsertionPoint).ifPresentOrElse(jwksDetectedIssue -> {
                    auditIssueConsumer.accept(jwksDetectedIssue);
                    perform(new CheckAlgConfusionExposedPublicKey(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                }, () -> {
                    // If no public key is exposed, it should be checked whether a forged public key can be used.
                    perform(new CheckAlgConfusionForgedPublicKey(), baseRequestResponse, auditInsertionPoint).ifPresent(auditIssueConsumer);
                });
            });
        });
    }

    /**
     * Runs a single check, catching and logging any exception it throws. A check that fails to complete (for
     * example, because of a network error or an unexpected response) should not prevent the remaining checks
     * in the chain from running.
     */
    private static Optional<AuditIssue> perform(Check check, HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        try {
            return check.perform(baseRequestResponse, auditInsertionPoint);
        } catch (Exception exc) {
            JwtScannerExtension.logging().logToError("%s failed with an exception and was skipped:".formatted(check.getClass().getSimpleName()));
            JwtScannerExtension.logging().logToError(exc);
            return Optional.empty();
        }
    }

}
