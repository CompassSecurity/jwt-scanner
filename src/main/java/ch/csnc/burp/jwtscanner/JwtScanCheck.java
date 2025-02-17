package ch.csnc.burp.jwtscanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import ch.csnc.burp.jwtscanner.JwtAuditIssues.JwtAuditIssue;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;

public class JwtScanCheck implements ScanCheck {

    private static final double SIMILARITY_THRESHOLD = 0.9;

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var matcher = Jwt.PATTERN.matcher(auditInsertionPoint.baseValue());
        var auditIssueList = new ArrayList<AuditIssue>();
        var jwt = new Jwt(auditInsertionPoint.baseValue());
        while (matcher.find()) {
            if (jwt.isExpired()) {
                var markers = markersOf(auditInsertionPoint, jwt.encode());
                auditIssueList.add(JwtAuditIssues.expired(AuditIssueConfidence.FIRM, baseRequestResponse.withRequestMarkers(markers)));
                activeAudit(baseRequestResponse, auditInsertionPoint, auditIssueList, jwt, JwtAuditIssues::expiredAccepted);
            }
            activeAudit(baseRequestResponse, auditInsertionPoint, auditIssueList, jwt.withRemovedSignature(), JwtAuditIssues::withoutSignature);
            var invalidSignatureAccepted = activeAudit(baseRequestResponse, auditInsertionPoint, auditIssueList, jwt.withWrongSignature(), JwtAuditIssues::invalidSignature);
            if (invalidSignatureAccepted) {
                // If a JWT is accepted with an invalid signature, further attacks, such as algorithm confusion attacks,
                // should not be attempted, as they will succeed regardless.
                return auditResult(auditIssueList);
            }
            for (var jwtWithAlgNone : jwt.withAlgNone()) {
                activeAudit(baseRequestResponse, auditInsertionPoint, auditIssueList, jwtWithAlgNone, JwtAuditIssues::algNone);
            }
            activeAudit(baseRequestResponse, auditInsertionPoint, auditIssueList, jwt.withEmptyPassword(), JwtAuditIssues::emptyPassword);
            activeAudit(baseRequestResponse, auditInsertionPoint, auditIssueList, jwt.withInvalidEcdsa(), JwtAuditIssues::invalidEcdsa);
            activeAudit(baseRequestResponse, auditInsertionPoint, auditIssueList, jwt.withInjectedJwkSelfSigned(), JwtAuditIssues::jwksInjection);
        }
        return auditResult(auditIssueList);
    }

    private boolean activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, List<AuditIssue> auditIssueList, Jwt jwt, JwtAuditIssue jwtAuditIssue) {
        var payload = byteArray(jwt.encode());
        var checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());
        var checkRequestResponse = JwtScannerExtension.api().http().sendRequest(checkRequest);
        var similarity = cosineSimilarityOf(baseRequestResponse, checkRequestResponse);
        if (baseRequestResponse.response().statusCode() == checkRequestResponse.response().statusCode()) {
            if (similarity.doubleValue() > SIMILARITY_THRESHOLD) {
                var markers = markersOf(auditInsertionPoint, payload);
                auditIssueList.add(jwtAuditIssue.get(AuditIssueConfidence.FIRM, baseRequestResponse, checkRequestResponse.withRequestMarkers(markers)));
                return true;
            }
        }
        return false;
    }

    private List<Marker> markersOf(AuditInsertionPoint auditInsertionPoint, String string) {
        return markersOf(auditInsertionPoint, byteArray(string));
    }

    private List<Marker> markersOf(AuditInsertionPoint auditInsertionPoint, ByteArray payload) {
        var highlights = auditInsertionPoint.issueHighlights(payload);
        var markers = new ArrayList<Marker>(highlights.size());
        for (var range : highlights) {
            var startIndex = range.startIndexInclusive();
            var endIndex = range.startIndexInclusive() + payload.length();
            markers.add(Marker.marker(startIndex, endIndex));
        }
        return markers;
    }

    private BigDecimal cosineSimilarityOf(HttpRequestResponse baseHttpRequestResponse, HttpRequestResponse checkRequestResponse) {
        return CosineSimilarity.of(baseHttpRequestResponse.response().toString(), checkRequestResponse.response().toString());
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        var auditIssues = new ArrayList<AuditIssue>();
        var matcher = Jwt.PATTERN.matcher(baseRequestResponse.request().toString());
        while (matcher.find()) {
            var marker = Marker.marker(matcher.start(), matcher.end());
            auditIssues.add(JwtAuditIssues.jwtDetected(AuditIssueConfidence.FIRM, baseRequestResponse.withRequestMarkers(marker)));
            var jwt = new Jwt(matcher.group());
            if (!jwt.hasExpiry()) {
                auditIssues.add(JwtAuditIssues.noExpiry(AuditIssueConfidence.FIRM, baseRequestResponse.withRequestMarkers(marker)));
            }
        }
        return auditResult(auditIssues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return KEEP_BOTH;
    }

}
