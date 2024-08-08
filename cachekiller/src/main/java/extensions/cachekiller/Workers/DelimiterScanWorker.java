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

    public DelimiterScanWorker(MontoyaApi api, HttpRequestResponse requestResponse, List<String> testDelimitersList, boolean fullSiteMap, boolean subHosts, boolean testKey){
        super(api, requestResponse, fullSiteMap, subHosts);
        this.testDelimitersList = new ArrayList<>(testDelimitersList);
        this.testKey = testKey;
    }

    public void scan(){
        HashMap<String, Server> servers = getServers();
        HttpRequestResponse reportReq;
        for (Server serv : servers.values()){
            reportReq = serv.detectOriginDelimiters(testDelimitersList);
            if (serv.getOriginDelimiters() != null) {
                StringBuilder sb = new StringBuilder();
                for (String del : serv.getOriginDelimiters()){
                    sb.append(printableStr(del));
                    sb.append("<br>");
                }
                reportIssue(reportReq, "Origin Delimiters Detected", "The following characters where detected as Origin Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION);
            }
            if (testKey) {
                reportReq = serv.detectKeyDelimiters(testDelimitersList);
                if (serv.getKeyDelimiters() != null) {
                    StringBuilder sb = new StringBuilder();
                    for (String del : serv.getKeyDelimiters()) {
                        sb.append(printableStr(del));
                        sb.append("<br>");
                    }
                    reportIssue(reportReq, "Key Delimiters Detected", "The following characters where detected as Cache Delimiters:<br>"+sb.toString()+"<br><br>The following paths appear to share the same network components and should be affected:<br>"+serv.requestsToString(), AuditIssueSeverity.INFORMATION);
                }
            }
        }
    }
}
