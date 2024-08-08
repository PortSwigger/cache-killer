package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import java.util.HashMap;

public class NormalizationScanWorker extends ScanWorker {

    public static final int SINGLE_DOT = 0;
    public static final int DOT_SEGMENT = 1;
    public static final int BACKSLASH_DOT_SEGMENT = 2;
    public static final int MULTI_SLASH = 3;
    public static final int BACK_SLASH = 4;
    public static final int ENCODED_SLASH = 5;
    public static final int ENCODED_BACKSLASH = 6;
    public static final int ENCODED_SEGMENT = 7;
    public static final int ENCODED_BACK_SEGMENT = 8;
    public static final int PATH_DECODING = 9;
    public static final int IS_QUERY_KEYED = 10;

    private final boolean testKey;

    public NormalizationScanWorker(MontoyaApi api, HttpRequestResponse requestResponse, boolean fullSiteMap, boolean subHosts, boolean testKey){
        super(api, requestResponse, fullSiteMap, subHosts);
        this.testKey = testKey;
    }

    public void scan(){
        HashMap<String, Server> servers = getServers();
        HttpRequestResponse reportReq;
        for (Server serv : servers.values()){
            reportReq = serv.detectOriginNormalization();
            if (serv.getOriginNormalization() != null) {
                boolean[] normalizations = serv.getOriginNormalization();
                StringBuilder sb = new StringBuilder();
                sb.append("The following Normalization behaviour was detected at the origin server:<br>");
                sb.append("Single dot normalized: ").append(normalizations[SINGLE_DOT] ? "YES - /a/./b == /a/b" : "NO").append("<br>");
                sb.append("Dot-segment normalized: ").append(normalizations[DOT_SEGMENT] ? "YES - /a/../b == /b" : "NO").append("<br>");
                sb.append("Backslash normalized: ").append(normalizations[BACK_SLASH] ? "YES - /a\\b == /a/b" : "NO").append("<br>");
                sb.append("Backslash dot-segment normalized: ").append(normalizations[BACKSLASH_DOT_SEGMENT] ? "YES - /a/..\\b == /b" : "NO").append("<br>");
                sb.append("Multi-slash removed: ").append(normalizations[MULTI_SLASH] ? "YES - /a////b == /b" : "NO").append("<br>");
                sb.append("Encoded slash normalized: ").append(normalizations[ENCODED_SLASH] ? "YES - /a%2Fb == /a/b" : "NO").append("<br>");
                sb.append("Encoded backslash normalized: ").append(normalizations[ENCODED_BACKSLASH] ? "YES - /a%5Cb == /a/b" : "NO").append("<br>");
                sb.append("Encoded dot-segment normalized: ").append(normalizations[ENCODED_SEGMENT] ? "YES - /a/..%2Fb == /b" : "NO").append("<br>");
                sb.append("Encoded backslash dot-segment normalized: ").append(normalizations[ENCODED_BACK_SEGMENT] ? "YES - /a/..%5Cb == /b" : "NO").append("<br>");
                sb.append("Path is URL decoded: ").append(normalizations[PATH_DECODING] ? "YES - /%68%65%6c%6c%6f == /hello" : "NO").append("<br>");
                sb.append("<br>The following paths appear to share the same network components and should be affected:<br>").append(serv.requestsToString());
                reportIssue(reportReq, "Origin Normalization Detected", sb.toString(), AuditIssueSeverity.INFORMATION);
            }
            if (testKey) {
                reportReq = serv.detectKeyNormalization();
                if (serv.getKeyNormalization() != null) {
                    boolean[] normalizations = serv.getKeyNormalization();
                    StringBuilder sb = new StringBuilder();
                    sb.append("The following Normalization behaviour was detected at the cache proxy:<br>");
                    sb.append("Single dot normalized: ").append(normalizations[SINGLE_DOT] ? "YES - /a/./b == /a/b" : "NO").append("<br>");
                    sb.append("Dot-segment normalized: ").append(normalizations[DOT_SEGMENT] ? "YES - /a/../b == /b" : "NO").append("<br>");
                    sb.append("Backslash normalized: ").append(normalizations[BACK_SLASH] ? "YES - /a\\b == /a/b" : "NO").append("<br>");
                    sb.append("Backslash dot-segment normalized: ").append(normalizations[BACKSLASH_DOT_SEGMENT] ? "YES - /a/..\\b == /b" : "NO").append("<br>");
                    sb.append("Multi-slash removed: ").append(normalizations[MULTI_SLASH] ? "YES - /a////b == /b" : "NO").append("<br>");
                    sb.append("Encoded slash normalized: ").append(normalizations[ENCODED_SLASH] ? "YES - /a%2Fb == /a/b" : "NO").append("<br>");
                    sb.append("Encoded backslash normalized: ").append(normalizations[ENCODED_BACKSLASH] ? "YES - /a%5Cb == /a/b" : "NO").append("<br>");
                    sb.append("Encoded dot-segment normalized: ").append(normalizations[ENCODED_SEGMENT] ? "YES - /a/..%2Fb == /b" : "NO").append("<br>");
                    sb.append("Encoded backslash dot-segment normalized: ").append(normalizations[ENCODED_BACK_SEGMENT] ? "YES - /a/..%5Cb == /b" : "NO").append("<br>");
                    sb.append("Path is URL decoded: ").append(normalizations[PATH_DECODING] ? "YES - /%68%65%6c%6c%6f == /hello" : "NO").append("<br>");
                    sb.append("Path is URL decoded: ").append(normalizations[IS_QUERY_KEYED] ? "YES - key(/hello?abc) == key(/hello)" : "NO").append("<br>");
                    sb.append("<br>The following paths appear to share the same network components and should be affected:<br>").append(serv.requestsToString());
                    reportIssue(reportReq, "Key Normalization Detected", sb.toString(), AuditIssueSeverity.INFORMATION);
                }
            }
        }
    }




}
