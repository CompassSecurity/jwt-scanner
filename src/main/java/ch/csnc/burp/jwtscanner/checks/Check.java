package ch.csnc.burp.jwtscanner.checks;

import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.CosineSimilarity;
import ch.csnc.burp.jwtscanner.Jwt;
import ch.csnc.burp.jwtscanner.JwtAuditIssues;
import ch.csnc.burp.jwtscanner.JwtAuditIssues.JwtAuditIssue;
import ch.csnc.burp.jwtscanner.JwtScannerExtension;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static burp.api.montoya.core.ByteArray.byteArray;

public abstract class Check {

    protected static final double SIMILARITY_THRESHOLD = 0.8;

    public abstract Optional<AuditIssue> check(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint);

    protected Optional<AuditIssue> check(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, Jwt jwt, JwtAuditIssue jwtAuditIssue) {
        var payload = byteArray(jwt.encode());
        var checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());
        var checkRequestResponse = JwtScannerExtension.api().http().sendRequest(checkRequest);
        var similarity = cosineSimilarityOf(baseRequestResponse, checkRequestResponse);
        var markers = markersOf(baseRequestResponse, auditInsertionPoint);
        if (baseRequestResponse.response().statusCode() == checkRequestResponse.response().statusCode()) {
            if (similarity.doubleValue() > SIMILARITY_THRESHOLD) {
                var auditIssue = jwtAuditIssue.get(jwt, AuditIssueConfidence.FIRM, baseRequestResponse, checkRequestResponse.withRequestMarkers(markers));
                return Optional.of(auditIssue);
            }
        } else if (checkRequestResponse.response().statusCode() == 500 && !checkRequestResponse.response().bodyToString().isBlank()) {
            // Server responded with 500 - Internal Server Error.
            // It might be worthwhile to have a more closer look at it.
            var auditIssue = JwtAuditIssues.internalServerError(jwt, AuditIssueConfidence.FIRM, baseRequestResponse, checkRequestResponse.withRequestMarkers(markers));
            return Optional.of(auditIssue);
        }
        return Optional.empty();
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
