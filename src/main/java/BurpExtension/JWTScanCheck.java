package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.LinkedList;
import java.util.List;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.Collections.singletonList;

class JWTScanCheck implements ScanCheck
{
    private final MontoyaApi api;

    JWTScanCheck(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint)
    {
        HttpRequest req = baseRequestResponse.request();
        HttpRequest checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(byteArray("Bearer " + "TEST-JWT"));
        api.logging().logToOutput("Request with payload: \n" + checkRequest);
        HttpRequestResponse checkRequestResponse = api.http().sendRequest(checkRequest);

        if (checkRequestResponse.response().statusCode() != 200) {
            api.logging().logToOutput("Request status code: " + checkRequestResponse.response().statusCode());
        };

        List<AuditIssue> auditIssueList = checkRequestResponse.response().statusCode() == 200 ? singletonList(
                auditIssue(
                        "JWT attack",
                        "Some JWT issue was found: ",
                        null,
                        baseRequestResponse.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        null,
                        AuditIssueSeverity.HIGH,
                        checkRequestResponse
                )
        ) : null;

        return auditResult(auditIssueList);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse)
    {
        return null;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue)
    {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }

    private static List<Marker> getResponseHighlights(HttpRequestResponse requestResponse, String match)
    {
        List<Marker> highlights = new LinkedList<>();
        String response = requestResponse.response().toString();

        int start = 0;

        while (start < response.length())
        {
            start = response.indexOf(match, start);

            if (start == -1)
            {
                break;
            }

            Marker marker = Marker.marker(start, start+match.length());
            highlights.add(marker);

            start += match.length();
        }

        return highlights;
    }
}
