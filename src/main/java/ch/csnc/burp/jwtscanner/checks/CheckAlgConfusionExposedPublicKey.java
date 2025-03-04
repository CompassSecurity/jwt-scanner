package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.JwtScannerExtension;
import ch.csnc.burp.jwtscanner.Rsa;

import java.util.Optional;

/**
 * Changes the algorithm from asymmetric (RS256) to symmetric
 * (HS256) and signs the JWT with the public key.
 * <p>
 * This uses the public key exposed by JWKS.
 */
public class CheckAlgConfusionExposedPublicKey extends Check {

    @Override
    public Optional<AuditIssue> check(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return JwtScannerExtension.storage().getJwk()
                .map(Rsa::publicKeyOf)
                .map(Rsa::publicKeyToPem)
                .map(secret -> Jwt.newBuilder(auditInsertionPoint.baseValue()).withHeader("alg", "HS256").withHS256Signature(secret).build())
                .flatMap(jwt -> check(baseRequestResponse, auditInsertionPoint, jwt, JwtAuditIssues::algConfusion));
    }

}
