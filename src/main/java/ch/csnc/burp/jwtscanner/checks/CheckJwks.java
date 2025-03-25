package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.*;

import java.net.URI;
import java.util.Optional;

import static ch.csnc.burp.jwtscanner.Gson.gson;

/**
 * Informational check that checks whether JSON Web Key Sets is exposed via jku header or
 * well-known directory.
 */
public class CheckJwks extends Check {

    @Override
    public Optional<AuditIssue> perform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var jwt = new Jwt(auditInsertionPoint.baseValue());

        if (jwt.getJwk().isPresent()) {
            this.handleJwk(jwt.getJwk().get());
            return Optional.of(JwtAuditIssues.jwkInHeaderDetected(jwt, AuditIssueConfidence.FIRM, baseRequestResponse));
        }

        if (jwt.getJku().isPresent()) {
            this.handleUrlToJwks(jwt, jwt.getJku().get());
            return Optional.of(JwtAuditIssues.jkuDetected(jwt, AuditIssueConfidence.FIRM, baseRequestResponse));
        }

        var url = baseRequestResponse.request().url();
        var uri = URI.create(url);

        var wellKnownJwksUrl = "%s://%s/jwks.json".formatted(uri.getScheme(), uri.getHost());
        var wellKnownJwksUrlRequestResponse = JwtScannerExtension.api().http().sendRequest(HttpRequest.httpRequestFromUrl(wellKnownJwksUrl));
        if (wellKnownJwksUrlRequestResponse.hasResponse() && wellKnownJwksUrlRequestResponse.response().statusCode() == 200) {
            this.handleJwksUrlRequestResponse(jwt, wellKnownJwksUrlRequestResponse);
            return Optional.of(JwtAuditIssues.jwksDetected(jwt, AuditIssueConfidence.FIRM, baseRequestResponse, wellKnownJwksUrlRequestResponse));
        }

        var jwksUrl = "%s://%s/.well-known/jwks.json".formatted(uri.getScheme(), uri.getHost());
        var jwksUrlRequestResponse = JwtScannerExtension.api().http().sendRequest(HttpRequest.httpRequestFromUrl(jwksUrl));
        if (jwksUrlRequestResponse.hasResponse() && jwksUrlRequestResponse.response().statusCode() == 200) {
            this.handleJwksUrlRequestResponse(jwt, jwksUrlRequestResponse);
            return Optional.of(JwtAuditIssues.jwksDetected(jwt, AuditIssueConfidence.FIRM, baseRequestResponse, jwksUrlRequestResponse));
        }

        return Optional.empty();
    }

    private void handleUrlToJwks(Jwt jwt, String url) {
        handleJwksUrlRequestResponse(jwt, JwtScannerExtension.api().http().sendRequest(HttpRequest.httpRequestFromUrl(url)));
    }

    private void handleJwksUrlRequestResponse(Jwt jwt, HttpRequestResponse requestResponse) {
        var response = requestResponse.response();
        if (response.statusCode() == 200) {
            var jwks = gson.fromJson(response.bodyToString(), Jwks.class);
            jwt.getKid().flatMap(jwks::forKid).ifPresent(this::handleJwk);
        }
    }

    private void handleJwk(Jwk jwk) {
        JwtScannerExtension.storage().putJwk(jwk);
    }

}
