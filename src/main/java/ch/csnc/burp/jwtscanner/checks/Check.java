package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.*;
import ch.csnc.burp.jwtscanner.JwtAuditIssues.JwtAuditIssue;

import java.awt.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static burp.api.montoya.core.ByteArray.byteArray;

public abstract class Check {

    protected static final double SIMILARITY_THRESHOLD = 0.8;

    public abstract Optional<AuditIssue> perform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint);

    protected Optional<AuditIssue> perform(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, String comment, Jwt jwt, JwtAuditIssue jwtAuditIssue) {
        var payload = byteArray(jwt.encode());
        var checkRequest = buildCheckRequest(baseRequestResponse, auditInsertionPoint, payload, comment);
        var checkRequestResponse = JwtScannerExtension.api().http().sendRequest(checkRequest);
        var similarity = cosineSimilarityOf(baseRequestResponse, checkRequestResponse);
        var markers = markersOf(baseRequestResponse, auditInsertionPoint);
        if (baseRequestResponse.response().statusCode() == checkRequestResponse.response().statusCode() && similarity.doubleValue() > SIMILARITY_THRESHOLD) {
            var auditIssue = jwtAuditIssue.get(jwt, AuditIssueConfidence.FIRM, baseRequestResponse, checkRequestResponse.withRequestMarkers(markers));
            return Optional.of(auditIssue);
        } else if (checkRequestResponse.response().statusCode() == 500 && !checkRequestResponse.response().bodyToString().isBlank()) {
            // Server responded with 500 - Internal Server Error.
            // It might be worthwhile to have a more closer look at it.
            var auditIssue = JwtAuditIssues.internalServerError(jwt, AuditIssueConfidence.FIRM, baseRequestResponse, checkRequestResponse.withRequestMarkers(markers));
            return Optional.of(auditIssue);
        }
        return Optional.empty();
    }

    protected HttpRequest buildCheckRequest(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, ByteArray payload, String comment) {
        var checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService()).withHeader(CommentHttpHandler.COMMENT_HEADER, comment);
        // The offset-based insertion point does not guarantee that the Content-Length header is
        // kept in sync when the payload placed into the body changes its length (e.g. a forged
        // JWT with an embedded JWK header can be considerably longer than the original). Without
        // fixing it up, the server may not read the full body (or waits for more bytes that never
        // arrive), so re-derive the header from the actual body via withBody(), which Burp
        // guarantees updates Content-Length.
        return checkRequest.withBody(checkRequest.body());
    }

    protected List<Marker> markersOf(HttpRequestResponse requestResponse, AuditInsertionPoint auditInsertionPoint) {
        var highlights = auditInsertionPoint.issueHighlights(requestResponse.request().toByteArray());
        var markers = new ArrayList<Marker>(highlights.size());
        for (var range : highlights) {
            markers.add(Marker.marker(range.startIndexInclusive(), range.endIndexExclusive()));
        }
        return markers;
    }

    protected BigDecimal cosineSimilarityOf(HttpRequestResponse baseHttpRequestResponse, HttpRequestResponse checkRequestResponse) {
        return CosineSimilarity.of(baseHttpRequestResponse.response().toString(), checkRequestResponse.response().toString());
    }

}
