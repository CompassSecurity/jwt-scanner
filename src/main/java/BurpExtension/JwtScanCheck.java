package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static java.util.Collections.emptyList;

class JwtScanCheck implements ScanCheck
{
    private final MontoyaApi api;

    JwtScanCheck(MontoyaApi api)
    {
        this.api = api;
    }

    ArrayList<String> algoList = new ArrayList<>();


    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return activeAudit(baseRequestResponse, auditInsertionPoint, false);
    }

    private List<Marker> markersForPayload(AuditInsertionPoint auditInsertionPoint, ByteArray payload) {
        List<Range> highlights = auditInsertionPoint.issueHighlights(payload);
        List<Marker> markers = new ArrayList<>(highlights.size());
        for (Range range : highlights) {
            int startIndex = range.startIndexInclusive();
            int endIndex = range.startIndexInclusive() + payload.length();
            markers.add(Marker.marker(startIndex, endIndex));
        }

        return markers;
    }

    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, boolean fromContextMenu) {
        // initialise list of AuditIssue
        List<AuditIssue> auditIssueList = new ArrayList<>();

        // obtain baseValue of insertion point
        String origJwt = auditInsertionPoint.baseValue();

        // verify that the insertion point represents a JWT as this ScanCheck performs transformations
        String jwtRegex = "(ey[a-zA-Z0-9_=]+)\\.(ey[a-zA-Z0-9_=\\-]+)\\.([a-zA-Z0-9_\\-+/=]*)";
        Pattern pattern = Pattern.compile(jwtRegex);
        Matcher matcher = pattern.matcher(origJwt);

        // insertion point has a valid JWT syntax
        if (matcher.find()) {

            JwtModifier jwtModifier = new JwtModifier(api);
            ByteArray payload;
            int successConfidence;

            // send base request
            HttpRequestResponse baseResponse = api.http().sendRequest(baseRequestResponse.request().withService(baseRequestResponse.httpService()));

            // determine if JWT is expired
            if (jwtModifier.isJwtExpired(origJwt)) {
                api.logging().raiseInfoEvent("The JWT is expired. Use a valid token for additional checks!");

                // if the server responds with 200, assume the request has been accepted
                if (baseResponse.response().statusCode() == 200){
                    List<Marker> markers = markersForPayload(auditInsertionPoint, byteArray(origJwt));
                    auditIssueList.add(JwtAuditIssues.expired(baseRequestResponse, baseResponse.withRequestMarkers(markers)));
                }

                return auditResult(auditIssueList);
            }

            // send JWT without signature
            payload = byteArray(jwtModifier.removeSignature(origJwt));
            HttpRequest checkRequestNoSig = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

            HttpRequestResponse checkRequestResponseNoSig = api.http().sendRequest(checkRequestNoSig);
            successConfidence = getSuccessConfidence(baseResponse,checkRequestResponseNoSig);

            if (requestWasSuccessful(baseResponse, checkRequestResponseNoSig,successConfidence)){
                List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                auditIssueList.add(JwtAuditIssues.withoutSignature(baseRequestResponse, checkRequestResponseNoSig.withRequestMarkers(markers),successConfidence));

                // no need for further checks
                return auditResult(auditIssueList);
            }

            // send JWT with invalid signature (skip for active scan)
            if (fromContextMenu) {
                payload = byteArray(jwtModifier.wrongSignature(origJwt));
                HttpRequest checkRequestSig = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

                HttpRequestResponse checkRequestResponseSig = api.http().sendRequest(checkRequestSig);
                successConfidence = getSuccessConfidence(baseResponse,checkRequestResponseSig);
                if (requestWasSuccessful(baseResponse, checkRequestResponseSig,successConfidence)) {
                    List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                    auditIssueList.add(JwtAuditIssues.invalidSignature(baseRequestResponse, checkRequestResponseSig.withRequestMarkers(markers),successConfidence));

                    // no need for further checks
                    return auditResult(auditIssueList);
                }
            }

            // send JWT with none algorithm (skip for active scan)
            if (fromContextMenu) {
                this.permute("none", "");
                for (String s : algoList) {
                    payload = byteArray(jwtModifier.algNone(origJwt, s));
                    HttpRequest checkRequestNone = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

                    HttpRequestResponse checkRequestResponseNone = api.http().sendRequest(checkRequestNone);
                    successConfidence = getSuccessConfidence(baseResponse,checkRequestResponseNone);
                    if (requestWasSuccessful(baseResponse, checkRequestResponseNone,successConfidence)) {
                        List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                        auditIssueList.add(JwtAuditIssues.getAlgNone(baseRequestResponse, checkRequestResponseNone.withRequestMarkers(markers),successConfidence));

                        // stop after a valid none permutation has been found
                        break;
                    }
                }
            }

            // send JWT with empty password
            payload = byteArray(jwtModifier.emptyPassword(origJwt));
            HttpRequest checkRequestEmpty = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

            HttpRequestResponse checkRequestResponseEmpty = api.http().sendRequest(checkRequestEmpty);
            successConfidence = getSuccessConfidence(baseResponse,checkRequestResponseEmpty);

            if (requestWasSuccessful(baseResponse, checkRequestResponseEmpty,successConfidence)){
                List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                auditIssueList.add(JwtAuditIssues.emptyPassword(baseRequestResponse, checkRequestResponseEmpty.withRequestMarkers(markers),successConfidence));
            }

            // send JWT with invalid ECDSA signature
            payload = byteArray(jwtModifier.invalidEcdsa(origJwt));
            HttpRequest checkRequestEcdsa = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

            HttpRequestResponse checkRequestResponseEcdsa = api.http().sendRequest(checkRequestEcdsa);
            successConfidence = getSuccessConfidence(baseResponse,checkRequestResponseEcdsa);
            if (requestWasSuccessful(baseResponse, checkRequestResponseEcdsa, successConfidence)){
                List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                auditIssueList.add(JwtAuditIssues.invalidEcdsa(baseRequestResponse, checkRequestResponseEcdsa.withRequestMarkers(markers),successConfidence));
            }

            // send JWT with JWKS injection (skip for active scan)
            if (fromContextMenu) {
                payload = byteArray(jwtModifier.jwksInjection(origJwt));
                HttpRequest checkRequestJwks = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

                HttpRequestResponse checkRequestResponseJwks = api.http().sendRequest(checkRequestJwks);
                successConfidence = getSuccessConfidence(baseResponse,checkRequestResponseJwks);
                if (requestWasSuccessful(baseResponse, checkRequestResponseJwks, successConfidence)) {
                    List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                    auditIssueList.add(JwtAuditIssues.jwksInjection(baseRequestResponse, checkRequestResponseJwks.withRequestMarkers(markers), successConfidence));
                }
            }
        }

        return auditResult(auditIssueList);
    }

    int getSuccessConfidence(HttpRequestResponse baseResponse, HttpRequestResponse requestResponse) {
        ResponseVariationsAnalyzer responseVariationsAnalyzer = api.http().createResponseVariationsAnalyzer();

        responseVariationsAnalyzer.updateWith(baseResponse.response());
        responseVariationsAnalyzer.updateWith(requestResponse.response());

        // Debug
        //api.logging().logToOutput("Orig Status code:" + baseResponse.response().statusCode());
        api.logging().logToOutput("New status code: " + requestResponse.response().statusCode());
        api.logging().logToOutput("Variations: " + responseVariationsAnalyzer.variantAttributes().size());
        for (AttributeType attribute : responseVariationsAnalyzer.variantAttributes()) {
            api.logging().logToOutput("     " + attribute.name());
        }
        return responseVariationsAnalyzer.variantAttributes().size();
    }

    boolean requestWasSuccessful(HttpRequestResponse baseResponse, HttpRequestResponse requestResponse, int successConfidence){
        return baseResponse.response().statusCode() == requestResponse.response().statusCode() && successConfidence <= 1;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> auditIssueList = emptyList();
        return auditResult(auditIssueList);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue)
    {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }

    private void permute(String ip, String op)
    {
        // base case
        if(ip.length() == 0){
            this.algoList.add(op);
            return;
        }
        // pick lower and uppercase
        String ch = ("" + ip.charAt(0)).toLowerCase();
        String ch2 = ("" + ip.charAt(0)).toUpperCase();
        ip = ip.substring(1, ip.length()) ;

        permute(ip, op + ch);
        permute(ip, op + ch2);
    }
}
