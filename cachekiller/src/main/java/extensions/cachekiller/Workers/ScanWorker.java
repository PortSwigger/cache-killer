package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import javax.swing.*;
import java.util.HashMap;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public abstract class ScanWorker extends SwingWorker<Void, Void> {

    protected final HttpRequestResponse requestResponse;
    protected final MontoyaApi api;
    protected final boolean fullSiteMap;
    protected final boolean subHosts;

    public ScanWorker(MontoyaApi api, HttpRequestResponse requestResponse, boolean fullSiteMap, boolean subHosts){
        this.api = api;
        this.requestResponse = requestResponse;
        this.fullSiteMap = fullSiteMap;
        this.subHosts = subHosts;
    }

    @Override
    protected Void doInBackground() {
        scan();
        return null;
    }

    public HashMap<String, Server> getServers(){
        HashMap<String, Server> servers = new HashMap<>();
        String host = requestResponse.httpService().host();
        if (fullSiteMap){
            for (HttpRequestResponse reqResp : api.siteMap().requestResponses()){
                if (!(reqResp.httpService().host().equals(host) || (subHosts && reqResp.httpService().host().endsWith("."+host)))) continue;
                HttpRequestResponse testReqResp = api.http().sendRequest(Server.addRequestCacheBuster(reqResp.request()));
                if (!testReqResp.hasResponse() || testReqResp.response().statusCode() == 0) continue;
                String serverHash = Server.getNetworkHash(testReqResp);
                if (servers.containsKey(serverHash)){
                    if (!(servers.get(serverHash).containsRequest(testReqResp.request()))) servers.get(serverHash).addRequestResponse(testReqResp);
                }
                else{
                    servers.put(serverHash, new Server(serverHash, api));
                    servers.get(serverHash).addRequestResponse(testReqResp);
                }
            }
        }
        else{
            HttpRequestResponse testReqResp = api.http().sendRequest(Server.addRequestCacheBuster(requestResponse.request()));
            if (testReqResp.hasResponse() && testReqResp.response().statusCode() != 0) {
                String serverHash = Server.getNetworkHash(testReqResp);
                servers.put(serverHash, new Server(serverHash, api));
                servers.get(serverHash).addRequestResponse(testReqResp);
            }
        }
        return servers;
    }

    public void reportIssue(HttpRequestResponse requestResponse, String title, String description, AuditIssueSeverity severity) {
        AuditIssue issue = auditIssue(
                title,
                description,
                null,
                requestResponse.request().url(),
                severity,
                AuditIssueConfidence.CERTAIN,
                null,
                null,
                AuditIssueSeverity.INFORMATION,
                requestResponse
        );
        api.siteMap().add(issue);
    }

    public static String strToHex(String input){
        StringBuilder hexString = new StringBuilder("0x");

        for (char ch : input.toCharArray()) {
            hexString.append(String.format("%02x", (int) ch));
        }

        return hexString.toString();
    }

    public static String printableStr(String str) {
        // Check if the character is a control character
        for (char ch : str.toCharArray()) {
            if (Character.isISOControl(ch)) {
                return strToHex(str);
            }

            // Check if the character is whitespace
            if (Character.isWhitespace(ch)) {
                continue;
            }

            // Check if the character is within the printable ASCII range
            if (ch >= 32 && ch <= 126) {
                continue;
            }

            // For Unicode characters, check general category
            int type = Character.getType(ch);
            if (!(type != Character.UNASSIGNED && type != Character.CONTROL && type != Character.FORMAT && type != Character.PRIVATE_USE && type != Character.SURROGATE && type != Character.LINE_SEPARATOR && type != Character.PARAGRAPH_SEPARATOR && type != Character.SPACE_SEPARATOR)) return strToHex(str);
        }
        return str;
    }

    abstract void scan();
}
