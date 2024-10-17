package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class DelimiterScanWorker extends ScanWorker {

    private final List<String> testDelimitersList;
    private final boolean testKey;

    public DelimiterScanWorker(MontoyaApi api, List<HttpRequestResponse> requestResponse, List<String> testDelimitersList, boolean fullSiteMap, boolean subHosts, boolean testKey){
        super(api, requestResponse, fullSiteMap, subHosts);
        this.testDelimitersList = new ArrayList<>(testDelimitersList);
        this.testKey = testKey;
    }

    public void scan(){
        api.logging().logToOutput("scan started");
        HashMap<String, Server> servers = getServers();
        HttpRequestResponse reportReq;
        for (Server serv : servers.values()){
            reportReq = serv.detectOriginDelimiters(testDelimitersList);
            if (serv.getOriginDelimiters() != null && !serv.getOriginDelimiters().isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (String del : serv.getOriginDelimiters()){
                    sb.append(printableStr(del));
                    sb.append("<br>");
                }
                reportIssue(reportReq, "Origin Delimiters Detected", "The following characters where detected as Origin Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION);
            }
            if (testKey) {
                reportReq = serv.detectKeyDelimiters(testDelimitersList);
                if (serv.getKeyDelimiters() != null && !serv.getKeyDelimiters().isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (String del : serv.getKeyDelimiters()) {
                        sb.append(printableStr(del));
                        sb.append("<br>");
                    }
                    reportIssue(reportReq, "Key Delimiters Detected", "The following characters where detected as Cache Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION);
                }
                else{
                    reportIssue(reportReq, "Key Delimiters", "None of the tested characters are used as Key Delimiters for the following paths that share the same network components.<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION);
                }
            }
        }
        api.logging().logToOutput("scan finished");
    }
}
