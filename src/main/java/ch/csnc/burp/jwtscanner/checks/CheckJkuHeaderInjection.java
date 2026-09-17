package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;

import java.util.Optional;

public class CheckJkuHeaderInjection extends Check {

    @Override
    protected Optional<AuditIssue> doPerform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        return perform(baseRequestResponse, auditInsertionPoint, "jku header injection", jwt.withInjectedJkuSelfSigned(), JwtAuditIssues::jkuHeaderInjection);
    }

}
