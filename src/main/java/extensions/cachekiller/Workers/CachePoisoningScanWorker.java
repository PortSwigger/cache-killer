package extensions.cachekiller.Workers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extensions.cachekiller.Utils.Server;

import java.util.*;

import static extensions.cachekiller.Utils.Server.sendHTTP1Request;

public class CachePoisoningScanWorker extends ScanWorker {

    private final List<String> testDelimitersList;

    public CachePoisoningScanWorker(MontoyaApi api, List<HttpRequestResponse> requestResponse, List<String> testDelimitersList, boolean subHosts){
        super(api, requestResponse, true, subHosts);
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
            List<String> discrepancyKeyDelimiters =  new ArrayList<>();
            for (String delim : serv.getOriginDelimiters()){
                if (!serv.getKeyDelimiters().contains(delim)) discrepancyOriginDelimiters.add(delim);
            }
            for (String delim : serv.getKeyDelimiters()){
                if (!serv.getOriginDelimiters().contains(delim)) discrepancyKeyDelimiters.add(delim);
            }
            if (serv.getKeyNormalization()[Server.DOT_SEGMENT]){
                for (String delim : discrepancyOriginDelimiters){
                    for (HttpRequestResponse reqResp : serv.getStaticRequest()){
                        String random = Server.randomNonce(5);
                        sendHTTP1Request(setPathSuffix(reqResp.request(), delim+"/../"+random));
                        sendHTTP1Request(setPathSuffix(reqResp.request(), delim+"/../"+random));
                        HttpRequestResponse testResp = sendHTTP1Request(reqResp.request().withPath(Server.removeLastSegment(reqResp.request().path())+"/"+random));
                        if (compareResp(testResp.response(), reqResp.response())){
                            reportIssue(testResp, "Web Cache Poisoning Detected", "The target appears to be normalizing the cache keys and its vulnerable to Web Cache Poisoning using the origin delimiter: '"+ScanWorker.printableStr(delim)+"'.", AuditIssueSeverity.HIGH);
                        }
                    }
                }
            }

            if (serv.getOriginNormalization()[Server.DOT_SEGMENT]){
                for (String delim : discrepancyKeyDelimiters){
                    for (HttpRequestResponse reqResp : serv.getStaticRequest()){
                        String random = Server.randomNonce(5);
                        sendHTTP1Request(reqResp.request().withPath("/"+random+delim+"/.."+reqResp.request().path()));
                        sendHTTP1Request(reqResp.request().withPath("/"+random+delim+"/.."+reqResp.request().path()));
                        HttpRequestResponse testResp = sendHTTP1Request(reqResp.request().withPath("/"+random));
                        if (compareResp(testResp.response(), reqResp.response())){
                            reportIssue(testResp, "Web Cache Poisoning Detected", "The target appears to be normalizing the path at the origin and its vulnerable to Web Cache Poisoning using the key delimiter: '"+ScanWorker.printableStr(delim)+"'.", AuditIssueSeverity.HIGH);
                        }
                    }
                }
            }
        }
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

}