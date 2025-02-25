package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.JwtScannerExtension;

import java.net.URI;
import java.util.Optional;

/**
 * Informational check that checks whether JSON Web Key Sets is exposed via jku header or
 * well-known directory.
 */
public class CheckJwks extends Check {

    @Override
    public Optional<AuditIssue> check(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        if (jwt.hasJku()) {
            return Optional.of(JwtAuditIssues.jkuDetected(jwt, AuditIssueConfidence.FIRM, baseRequestResponse));
        }
        var url = baseRequestResponse.request().url();
        var uri = URI.create(url);
        var wellKnownJwksUrl = "%s://%s/jwks.json".formatted(uri.getScheme(), uri.getHost());
        var jwksUrl = "%s://%s/.well-known/jwks.json".formatted(uri.getScheme(), uri.getHost());
        var http = JwtScannerExtension.api().http();
        var wellKnownJwksUrlRequestResponse = http.sendRequest(HttpRequest.httpRequestFromUrl(wellKnownJwksUrl));
        if (wellKnownJwksUrlRequestResponse.hasResponse() && wellKnownJwksUrlRequestResponse.response().statusCode() == 200) {
            return Optional.of(JwtAuditIssues.jwksDetected(jwt, AuditIssueConfidence.FIRM, baseRequestResponse, wellKnownJwksUrlRequestResponse));
        }
        var jwksUrlRequestResponse = http.sendRequest(HttpRequest.httpRequestFromUrl(jwksUrl));
        if (jwksUrlRequestResponse.hasResponse() && jwksUrlRequestResponse.response().statusCode() == 200) {
            return Optional.of(JwtAuditIssues.jwksDetected(jwt, AuditIssueConfidence.FIRM, baseRequestResponse, jwksUrlRequestResponse));
        }
        return Optional.empty();
    }

}
