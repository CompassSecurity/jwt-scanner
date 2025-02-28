package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.Rsa;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static ch.csnc.burp.jwtscanner.Base64.base64EncoderWithPadding;

/**
 * Changes the algorithm from asymmetric (RS256) to symmetric
 * (HS256) and signs the JWT with the public key (base64 encoded PEM).
 */
public class CheckAlgorithmConfusion extends Check {

    @Override
    public Optional<AuditIssue> check(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return Rsa.retrievePublicKeyOfJwk()
                .map(Rsa::publicKeyToPem)
                .map(secret -> Jwt.newBuilder(auditInsertionPoint.baseValue()).withHeader("alg", "HS256").withHS256Signature(secret).build())
                .flatMap(jwt -> check(baseRequestResponse, auditInsertionPoint, jwt, JwtAuditIssues::algConfusion));
    }

}
