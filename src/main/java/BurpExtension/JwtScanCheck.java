package BurpExtension;

import burp.api.montoya.MontoyaApi;
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
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint)
    {
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

            // determine if JWT is not expired
            if (jwtModifier.isJwtNotExpired(origJwt)) {
                // Debug output
                api.logging().logToOutput("JWT in original request:\n" + origJwt);
            } else {
                api.logging().raiseInfoEvent("Expired JWT identified. Use a valid token for additional checks!");

                // send the expired JWT again to determine if the server accepts it
                HttpRequest checkRequestExpired = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(origJwt)).withService(baseRequestResponse.httpService());
                HttpRequestResponse checkRequestResponseSig = api.http().sendRequest(checkRequestExpired);
                if (checkRequestResponseSig.response().statusCode() == 200){
                    auditIssueList.add(JwtAuditIssues.expired(baseRequestResponse, checkRequestResponseSig));
                }

                return auditResult(auditIssueList);
            }

            // send JWT without signature
            HttpRequest checkRequestNoSig = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.removeSignature(origJwt))).withService(baseRequestResponse.httpService());
            HttpRequestResponse checkRequestResponseNoSig = api.http().sendRequest(checkRequestNoSig);
            if (requestWasSuccessful(checkRequestResponseNoSig)){
                auditIssueList.add(JwtAuditIssues.withoutSignature(baseRequestResponse, checkRequestResponseNoSig));

                // no need for further checks
                return auditResult(auditIssueList);
            }

            // send JWT with invalid signature
            HttpRequest checkRequestSig = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.wrongSignature(origJwt))).withService(baseRequestResponse.httpService());
            HttpRequestResponse checkRequestResponseSig = api.http().sendRequest(checkRequestSig);
            if (requestWasSuccessful(checkRequestResponseSig)) {
                auditIssueList.add(JwtAuditIssues.invalidSignature(baseRequestResponse, checkRequestResponseSig));

                // no need for further checks
                return auditResult(auditIssueList);
            }

            // send JWT with none algorithm
            this.permute("none", "");
            for (String s : algoList) {
                HttpRequest checkRequestNone = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.algNone(origJwt, s))).withService(baseRequestResponse.httpService());
                HttpRequestResponse checkRequestResponseNone = api.http().sendRequest(checkRequestNone);
                if (requestWasSuccessful(checkRequestResponseNone)) {
                    auditIssueList.add(JwtAuditIssues.getAlgNone(baseRequestResponse, checkRequestResponseNone));

                    // stop after a valid none permutation has been found
                    break;
                }
            }

            // send JWT with empty password
            HttpRequest checkRequestEmpty = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.emptyPassword(origJwt))).withService(baseRequestResponse.httpService());
            HttpRequestResponse checkRequestResponseEmpty = api.http().sendRequest(checkRequestEmpty);
            if (requestWasSuccessful(checkRequestResponseEmpty)){
                auditIssueList.add(JwtAuditIssues.emptyPassword(baseRequestResponse, checkRequestResponseEmpty));
            }

            // send JWT with invalid ECDSA signature
            HttpRequest checkRequestEcdsa = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.invalidEcdsa(origJwt))).withService(baseRequestResponse.httpService());
            HttpRequestResponse checkRequestResponseEcdsa = api.http().sendRequest(checkRequestEcdsa);
            if (requestWasSuccessful(checkRequestResponseEcdsa)){
                auditIssueList.add(JwtAuditIssues.invalidEcdsa(baseRequestResponse, checkRequestResponseEcdsa));
            }

            // send JWT with JWKS injection
            HttpRequest checkRequestJwks = auditInsertionPoint.buildHttpRequestWithPayload(byteArray(jwtModifier.jwksInjection(origJwt))).withService(baseRequestResponse.httpService());
            HttpRequestResponse checkRequestResponseJwks = api.http().sendRequest(checkRequestJwks);
            if (requestWasSuccessful(checkRequestResponseJwks)){
                auditIssueList.add(JwtAuditIssues.jwksInjection(baseRequestResponse, checkRequestResponseJwks));
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
