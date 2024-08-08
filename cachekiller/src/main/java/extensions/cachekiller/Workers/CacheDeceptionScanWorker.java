package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class CacheDeceptionScanWorker extends ScanWorker {

    private final List<String> testDelimitersList;
    private final List<String> extensions;
    private List<String> staticDirs;
    public static final List<Character> BROWSER_ENCODED = new ArrayList<>(Arrays.asList('"', '^', '{', '}', '`','|','<','>','#','?','\\'));


    public CacheDeceptionScanWorker(MontoyaApi api, HttpRequestResponse requestResponse, List<String> testDelimitersList, boolean subHosts, List<String> extensions, List<String> staticDirs){
        super(api, requestResponse, true, subHosts);
        this.extensions = new ArrayList<>(extensions);
        if (staticDirs == null) this.staticDirs = null;
        else this.staticDirs = new ArrayList<>(staticDirs);
        this.testDelimitersList = new ArrayList<>(testDelimitersList);
    }

    public void scan(){
        HashMap<String, Server> servers = getServers();
        for (Server serv : servers.values()){
            serv.detectOriginDelimiters(testDelimitersList);
            serv.detectKeyDelimiters(testDelimitersList);
            serv.detectOriginNormalization();
            serv.detectKeyNormalization();
            List<String> discrepancyOriginDelimiters = new ArrayList<>();
            for (String delim : serv.getOriginDelimiters()){
                if (isSentByBrowser(delim) && !serv.getKeyDelimiters().contains(delim)) discrepancyOriginDelimiters.add(delim);
            }
            List<HttpRequestResponse> vulnerableExtension;
            for (String delim : discrepancyOriginDelimiters){
                vulnerableExtension = testExtensionRule(serv, delim, this.extensions);
                for (HttpRequestResponse vuln : vulnerableExtension){
                    reportIssue(vuln, "Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception using the Delimiter: '"+ScanWorker.printableStr(delim)+"' and the Static Extensions rule<br><br>If the response contains sensitive information this could be used to hijack victim's data.", AuditIssueSeverity.HIGH);
                }
            }
            if (this.staticDirs == null) this.staticDirs = new ArrayList<>(detectStaticDirectories(serv));

            this.staticDirs.add("/robots.txt");
            this.staticDirs.add("/favicon.ico");
            this.staticDirs.add("/index.html");
            this.staticDirs.add("/home");

            if (serv.getKeyNormalization()[Server.ENCODED_SEGMENT] && !serv.getOriginNormalization()[Server.ENCODED_SEGMENT]){
                for (HttpRequestResponse reqResp : serv.getDynamicRequest()) {
                    if (reqResp.request().pathWithoutQuery().length()<2) continue;
                    for (String dir : this.staticDirs) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(dir);
                        if (!dir.endsWith("/")) sb.append("/");
                        for (String s : Server.splitPathSegments(dir)) {
                            sb.append("..%2F");
                        }
                        sb.append(reqResp.request().path().substring(1));
                        HttpRequestResponse testReq = api.http().sendRequest(reqResp.request().withPath(sb.toString()));
                        if (detectCacheDeception(testReq, reqResp)){
                            reportIssue(testReq, "Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception with Cache Rule Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.", AuditIssueSeverity.HIGH);
                        }
                    }
                }
            }

            if (serv.getKeyNormalization()[Server.ENCODED_BACK_SEGMENT] && !serv.getOriginNormalization()[Server.ENCODED_BACK_SEGMENT]){
                for (HttpRequestResponse reqResp : serv.getDynamicRequest()) {
                    if (reqResp.request().pathWithoutQuery().length()<2) continue;
                    for (String dir : this.staticDirs) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(dir);
                        if (!dir.endsWith("/")) sb.append("/");
                        for (String s : Server.splitPathSegments(dir)) {
                            sb.append("..%5C");
                        }
                        sb.append(reqResp.request().path().substring(1));
                        HttpRequestResponse testReq = api.http().sendRequest(reqResp.request().withPath(sb.toString()));
                        if (detectCacheDeception(testReq, reqResp)){
                            reportIssue(testReq, "Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception with Cache Rule Backslash Normalization.<br>The path : '"+dir+"' appears to be a Static Directory.", AuditIssueSeverity.HIGH);
                        }
                    }
                }
            }

            if (!serv.getKeyNormalization()[Server.ENCODED_SEGMENT] && serv.getOriginNormalization()[Server.ENCODED_SEGMENT]){
                for (HttpRequestResponse reqResp : serv.getDynamicRequest()) {
                    if (reqResp.request().pathWithoutQuery().length()<2) continue;
                    for (String dir : this.staticDirs) {
                        for (String delimiter : serv.getOriginDelimiters()) {
                            StringBuilder sb = new StringBuilder();
                            sb.append(reqResp.request().pathWithoutQuery());
                            if (!reqResp.request().pathWithoutQuery().endsWith("/")) sb.append("/");
                            sb.append(delimiter);
                            for (String s : Server.splitPathSegments(reqResp.request().pathWithoutQuery())) {
                                sb.append("%2E%2E%2F");
                            }
                            sb.append(dir.substring(1));
                            HttpRequestResponse testReq = api.http().sendRequest(reqResp.request().withPath(sb.toString()));
                            if (detectCacheDeception(testReq, reqResp)) {
                                reportIssue(testReq, "Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception with Origin Server Normalization.<br>The path : '" + dir + "' appears to be a Static Directory.<br>The Origin Delimiter used is: "+delimiter, AuditIssueSeverity.HIGH);
                            }
                        }
                    }
                }
            }

            if (!serv.getKeyNormalization()[Server.ENCODED_BACK_SEGMENT] && serv.getOriginNormalization()[Server.ENCODED_BACK_SEGMENT]){
                for (HttpRequestResponse reqResp : serv.getDynamicRequest()) {
                    if (reqResp.request().pathWithoutQuery().length()<2) continue;
                    for (String dir : this.staticDirs) {
                        for (String delimiter : serv.getOriginDelimiters()) {
                            StringBuilder sb = new StringBuilder();
                            sb.append(reqResp.request().pathWithoutQuery());
                            if (!reqResp.request().pathWithoutQuery().endsWith("/")) sb.append("/");
                            sb.append(delimiter);
                            for (String s : Server.splitPathSegments(reqResp.request().pathWithoutQuery())) {
                                sb.append("%2E%2E%5C");
                            }
                            sb.append(dir.substring(1));
                            HttpRequestResponse testReq = api.http().sendRequest(reqResp.request().withPath(sb.toString()));
                            if (detectCacheDeception(testReq, reqResp)) {
                                reportIssue(testReq, "Web Cache Deception Detected", "The target appears to be vulnerable to Web Cache Deception with Origin Server Backslash Normalization.<br>The path : '" + dir + "' appears to be a Static Directory.<br>The Origin Delimiter used is: "+delimiter, AuditIssueSeverity.HIGH);
                            }
                        }
                    }
                }
            }

        }
    }


    public List<HttpRequestResponse> testExtensionRule(Server server, String delimiter, List<String> extensions){
        List<HttpRequestResponse> out = new ArrayList<>();
        for (HttpRequestResponse reqResp : server.getDynamicRequest()) {
            HttpRequestResponse testReq = api.http().sendRequest(setPathSuffix(reqResp.request(), delimiter+(delimiter.equals(".") ? ".": "")+"aaaaa"));
            if (testReq.hasResponse() && testReq.response().statusCode() != 0 && compareResp(testReq.response(), reqResp.response())) {
                for (String ext : extensions) {
                    testReq = api.http().sendRequest(setPathSuffix(reqResp.request(), delimiter + (delimiter.equals(".") ? "." : "") + ext));
                    boolean cached = triggerCache(testReq.request());
                    testReq = api.http().sendRequest(testReq.request());
                    if (cached || !containSameCacheHeaders(testReq, reqResp)) {
                        out.add(testReq);
                    }
                }
            }
        }
        return out;
    }

    public boolean detectCacheDeception(HttpRequestResponse testReq, HttpRequestResponse baseReqResp){
        if (testReq.hasResponse() && testReq.response().statusCode() != 0 && compareResp(testReq.response(), baseReqResp.response())) {
            boolean cached = triggerCache(testReq.request());
            testReq = api.http().sendRequest(testReq.request());
            return cached || !containSameCacheHeaders(testReq, baseReqResp);
        }
        return false;
    }


    public boolean triggerCache(HttpRequest request){
        boolean done = false;
        HttpRequestResponse testGet = api.http().sendRequest(request);
        if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        if (!done) {
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException ignored) {
            }
            testGet = api.http().sendRequest(testGet.request());
            if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        }
        if (!done) {
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException ignored) {
            }
            testGet = api.http().sendRequest(testGet.request());
            if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        }
        while (!(testGet.hasResponse() && testGet.response().statusCode() != 0)){
            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException ignored) {
            }
            testGet = api.http().sendRequest(testGet.request());
            if (testGet.hasResponse() && hasCacheHit(testGet.response())) done = true;
        }
        return done;
    }

    public static boolean hasCacheHit(HttpResponse cacheableResponse) {

        for (HttpHeader hdr : cacheableResponse.headers()) {
            String name = hdr.name().toLowerCase();
            String value = hdr.value().toLowerCase();
            if ((name.contains("-cache-") || name.startsWith("cache-") || name.endsWith("-cache") || name.contains("server-timing")) && (value.toLowerCase().contains("hit") || value.toLowerCase().contains("served"))) {
                return true;
            }
        }

        return cacheableResponse.hasHeader("Age");
    }


    public Map<String, String> getCacheHeaders(HttpResponse cacheableResponse){
        Map<String, String> headers = new HashMap<>();
        for (HttpHeader hdr : cacheableResponse.headers()) {
            String name = hdr.name().toLowerCase();
            String value = hdr.value().toLowerCase();
            if ((name.contains("-cache-") || name.startsWith("cache-") || name.endsWith("-cache")) && (value.toLowerCase().contains("hit"))) {
                headers.put(hdr.name(), hdr.value());
            }
        }
        return headers;
    }

    public boolean containSameCacheHeaders(HttpRequestResponse r1, HttpRequestResponse r2){
        Map<String, String> h1, h2;
        h1 = getCacheHeaders(r1.response());
        h2 = getCacheHeaders(r2.response());
        for (String name : h1.keySet()){
            if (!h2.containsKey(name)) return false;
            if (!h1.get(name).equals(h2.get(name))) return false;
            h2.remove(name);
        }
        return true;
    }

    public static boolean compareResp(HttpResponse r1, HttpResponse r2){
        return  (r1 != null && r2 != null && r1.statusCode() != 0 && r1.statusCode() == r2.statusCode() && (Math.abs(r1.body().length()-r2.body().length())<20) && compareHeader(r1, r2, "content-type") && compareHeader(r1, r2, "server") && compareHeader(r1, r2, "vary"));
    }

    public static boolean compareHeader(HttpResponse r1, HttpResponse r2, String header){
        if (r1 != null && r2 != null){
            if (r1.hasHeader(header) && r2.hasHeader(header)){
                return r1.header(header).value().equals(r2.header(header).value());
            }
            else return (r1.hasHeader(header) == r2.hasHeader(header));
        }
        else return (r1 == r2);
    }
    public static HttpRequest setPathSuffix(HttpRequest base, String suffix){
        if (!base.path().contains("?")) return base.withPath(base.path()+suffix);
        return base.withPath(base.path().substring(0, base.path().indexOf("?"))+suffix+base.path().substring(base.path().indexOf("?")));
    }

    public static boolean isSentByBrowser(String delimiter){
        for (char c : delimiter.toCharArray()){
            if (BROWSER_ENCODED.contains(c)) return false;
            if (c<32 || c>126) return false;
        }
        return true;
    }

    public List<String> detectStaticDirectories(Server server){
        List<String> out = new ArrayList<>();
        for (String path : server.getStaticRequestURLs()){
            ArrayList<String> segments = Server.splitPathSegments(path);
            if (!segments.isEmpty()) out.add(segments.getFirst());
        }
        return out;
    }

}