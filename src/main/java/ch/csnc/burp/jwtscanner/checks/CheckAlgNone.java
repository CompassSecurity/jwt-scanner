package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;

import java.util.Optional;

/**
 * Checks whether JWT with alg 'none', 'NONE', 'NoNe', 'nOne', etc is accepted.
 */
public class CheckAlgNone extends Check {

    @Override
    public Optional<AuditIssue> perform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        for (var jwtWithAlgNone : jwt.withAlgNone()) {
            var auditIssue = perform(baseRequestResponse, auditInsertionPoint, "alg %s".formatted(jwtWithAlgNone.getAlg().orElse("")), jwtWithAlgNone, JwtAuditIssues::algNone);
            if (auditIssue.isPresent()) {
                return auditIssue;
            }
        }
        return Optional.empty();
    }

}
