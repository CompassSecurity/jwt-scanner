package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

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
        if (checkRequestResponse.response().statusCode() == 200){
            api.siteMap().add(auditIssue("Wrong JWT attack",
                    "Some JWT issue was found: ",
                    "Validate the JWT correctly!",
                    baseRequestResponse.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.CERTAIN,
                    null,
                    null,
                    AuditIssueSeverity.HIGH,
                    checkRequestResponse));
        }

        return null;
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
}
