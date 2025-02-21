package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;

import java.util.Optional;

/**
 * Checks whether a JWT symmetrically signed with empty password is accepted.
 */
public class CheckEmptyPassword extends Check {

    @Override
    public Optional<AuditIssue> check(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        return check(baseRequestResponse, auditInsertionPoint, jwt.withEmptyPassword(), JwtAuditIssues::emptyPassword);
    }

}
