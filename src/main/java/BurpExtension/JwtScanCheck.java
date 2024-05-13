package BurpExtension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
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
            markers.add(Marker.marker(range));
        }

        return markers;
    }

    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint, boolean fromContextMenu) {
        // initialise list of AuditIssue
        List<AuditIssue> auditIssueList = new ArrayList<>();

        // obtain baseValue of insertion point
        String origJwt = auditInsertionPoint.baseValue();

        // verify that the insertion point represents a JWT as this ScanCheck performs transformations
        String jwtRegex = "(ey[a-zA-Z0-9_=]+)\\.(ey[a-zA-Z0-9_=]+)\\.([a-zA-Z0-9_\\-+/=]*)";
        Pattern pattern = Pattern.compile(jwtRegex);
        Matcher matcher = pattern.matcher(origJwt);

        // insertion point has a valid JWT syntax
        if (matcher.find()) {

            JwtModifier jwtModifier = new JwtModifier(api);
            ByteArray payload;

            // determine if JWT is not expired
            if (jwtModifier.isJwtNotExpired(origJwt)) {
                // Debug output
                api.logging().logToOutput("JWT in original request:\n" + origJwt);
            } else {
                api.logging().raiseInfoEvent("Expired JWT identified. Use a valid token for additional checks!");

                // send the expired JWT again to determine if the server accepts it
                payload = byteArray(origJwt);
                HttpRequest checkRequestExpired = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

                HttpRequestResponse checkRequestResponseSig = api.http().sendRequest(checkRequestExpired);
                if (checkRequestResponseSig.response().statusCode() == 200){
                    List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                    auditIssueList.add(JwtAuditIssues.expired(baseRequestResponse, checkRequestResponseSig.withRequestMarkers(markers)));
                }

                return auditResult(auditIssueList);
            }

            // send JWT without signature
            payload = byteArray(jwtModifier.removeSignature(origJwt));
            HttpRequest checkRequestNoSig = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

            HttpRequestResponse checkRequestResponseNoSig = api.http().sendRequest(checkRequestNoSig);
            if (requestWasSuccessful(checkRequestResponseNoSig)){
                List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                auditIssueList.add(JwtAuditIssues.withoutSignature(baseRequestResponse, checkRequestResponseNoSig.withRequestMarkers(markers)));

                // no need for further checks
                return auditResult(auditIssueList);
            }

            // send JWT with invalid signature (skip for active scan)
            if (fromContextMenu) {
                payload = byteArray(jwtModifier.wrongSignature(origJwt));
                HttpRequest checkRequestSig = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

                HttpRequestResponse checkRequestResponseSig = api.http().sendRequest(checkRequestSig);
                if (requestWasSuccessful(checkRequestResponseSig)) {
                    List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                    auditIssueList.add(JwtAuditIssues.invalidSignature(baseRequestResponse, checkRequestResponseSig.withRequestMarkers(markers)));

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
                    if (requestWasSuccessful(checkRequestResponseNone)) {
                        List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                        auditIssueList.add(JwtAuditIssues.getAlgNone(baseRequestResponse, checkRequestResponseNone.withRequestMarkers(markers)));

                        // stop after a valid none permutation has been found
                        break;
                    }
                }
            }

            // send JWT with empty password
            payload = byteArray(jwtModifier.emptyPassword(origJwt));
            HttpRequest checkRequestEmpty = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

            HttpRequestResponse checkRequestResponseEmpty = api.http().sendRequest(checkRequestEmpty);
            if (requestWasSuccessful(checkRequestResponseEmpty)){
                List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                auditIssueList.add(JwtAuditIssues.emptyPassword(baseRequestResponse, checkRequestResponseEmpty.withRequestMarkers(markers)));
            }

            // send JWT with invalid ECDSA signature
            payload = byteArray(jwtModifier.invalidEcdsa(origJwt));
            HttpRequest checkRequestEcdsa = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

            HttpRequestResponse checkRequestResponseEcdsa = api.http().sendRequest(checkRequestEcdsa);
            if (requestWasSuccessful(checkRequestResponseEcdsa)){
                List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                auditIssueList.add(JwtAuditIssues.invalidEcdsa(baseRequestResponse, checkRequestResponseEcdsa.withRequestMarkers(markers)));
            }

            // send JWT with JWKS injection (skip for active scan)
            if (fromContextMenu) {
                payload = byteArray(jwtModifier.jwksInjection(origJwt));
                HttpRequest checkRequestJwks = auditInsertionPoint.buildHttpRequestWithPayload(payload).withService(baseRequestResponse.httpService());

                HttpRequestResponse checkRequestResponseJwks = api.http().sendRequest(checkRequestJwks);
                if (requestWasSuccessful(checkRequestResponseJwks)) {
                    List<Marker> markers = markersForPayload(auditInsertionPoint, payload);
                    auditIssueList.add(JwtAuditIssues.jwksInjection(baseRequestResponse, checkRequestResponseJwks.withRequestMarkers(markers)));
                }
            }
        }

        return auditResult(auditIssueList);
    }

    boolean requestWasSuccessful(HttpRequestResponse requestResponse) {
        return (requestResponse.response().statusCode() == 200);
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
