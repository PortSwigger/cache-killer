package extensions.cachekiller.Utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;


public class Server {

    public static final List<String> BAD_CHARS = new ArrayList<>(Arrays.asList(""+(char)0x00, "%00", ""+(char)0x7F, "#", "\tabc", "%xx", " abcd", "?<>", "/a/b/c/d/e/../../../../../f" ,"\r", "\n"));
    public static final List<String> SERVER_KEYWORDS = new ArrayList<>(Arrays.asList("cloudflare", "cloudfront", "azure", "nginx", "apache", "microsoft", "google", "fastly", "imperva", "akamai", "java", "puma", "x-amz"));
    public static final List<String> STATIC_EXTENSIONS  = new ArrayList<>(Arrays.asList("7Z",  "CSV",  "GIF",  "MIDI",  "PNG",  "TIF",  "ZIP", "AVI",  "DOC",  "GZ",  "MKV",  "PPT",  "TIFF",  "ZST", "AVIF",  "DOCX",  "ICO",  "MP3",  "PPTX",  "TTF",  "APK",  "DMG",  "ISO",  "MP4",  "PS",  "WEBM",  "BIN",  "EJS",  "JAR",  "OGG",  "RAR",  "WEBP",  "BMP",  "EOT",  "JPG",  "OTF",  "SVG",  "WOFF",  "BZ2",  "EPS",  "JPEG",  "PDF",  "SVGZ",  "WOFF2",  "CLASS",  "EXE",  "JS",  "PICT",  "SWF",  "XLS",  "CSS",  "FLAC",  "MID",  "PLS",  "TAR",  "XLSX"));

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

    private final String hash;
    private static MontoyaApi api;
    private List<String> originDelimiters;
    private List<String> keyDelimiters;
    boolean[] originNormalization;
    boolean[] keyNormalization;

    ArrayList<HttpRequestResponse> staticReqs;
    ArrayList<HttpRequestResponse> dynamicReqs;

    public Server(String hash, MontoyaApi api){
        Server.api = api;
        this.hash = hash;
        originDelimiters = null;
        keyDelimiters = null;
        originNormalization = null;
        keyNormalization = null;
        staticReqs = new ArrayList<>();
        dynamicReqs = new ArrayList<>();
    }

    public List<HttpRequestResponse> getStaticRequest(){
        return this.staticReqs;
    }

    public List<HttpRequestResponse> getDynamicRequest(){
        return this.dynamicReqs;
    }

    public List<String> getOriginDelimiters(){
        return this.originDelimiters;
    }

    public List<String> getKeyDelimiters(){
        return this.keyDelimiters;
    }

    public List<String> getRequestURLs(){
        ArrayList<String> out = new ArrayList<>();
        for (HttpRequestResponse reqResp : this.staticReqs){
            out.add(reqResp.request().path());
        }
        for (HttpRequestResponse reqResp : this.dynamicReqs){
            out.add(reqResp.request().path());
        }
        return out;
    }

    public List<String> getStaticRequestURLs(){
        ArrayList<String> out = new ArrayList<>();
        for (HttpRequestResponse reqResp : this.staticReqs){
            out.add(reqResp.request().path());
        }
        return out;
    }

    public String requestsToString(){
        StringBuilder urls = new StringBuilder();
        List<String> reqList = getRequestURLs();
        for (String path : reqList){
            urls.append(path).append("<br>");
        }
        return urls.toString();
    }


    public static ArrayList<String> detectOriginDelimiters(HttpRequestResponse baseReqResp, List<String> delimiters){
        //For better results use a non-cacheable request/response
        ArrayList<String> out = new ArrayList<>();
        if (!baseReqResp.hasResponse() || baseReqResp.response().statusCode()==0 || baseReqResp.response().statusCode()>=400) return null;
        HttpRequestResponse notfound = api.http().sendRequest(baseReqResp.request().withPath(baseReqResp.request().pathWithoutQuery()+randomNonce(9)+getQuery(baseReqResp.request())));
        if (!notfound.hasResponse() || notfound.response().statusCode()==0) return null;
        if (baseReqResp.response().statusCode() == notfound.response().statusCode()) return null;

        for (String delim : delimiters) {
            HttpRequestResponse testReqResp = api.http().sendRequest(baseReqResp.request().withPath(baseReqResp.request().pathWithoutQuery() + delim + randomNonce(9) + getQuery(baseReqResp.request())));
            if (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response())) {
                out.add(delim);
            }
        }
        return out;
    }

    public HttpRequestResponse detectOriginDelimiters(List<String> delimiters){
        for (HttpRequestResponse reqResp : this.dynamicReqs){
            List<String> originDelimiters = detectOriginDelimiters(reqResp, delimiters);
            if (originDelimiters != null) {
                this.originDelimiters = originDelimiters;
                return reqResp;
            }
        }
        for (HttpRequestResponse reqResp : this.staticReqs){
            List<String> originDelimiters = detectOriginDelimiters(reqResp, delimiters);
            if (originDelimiters != null) {
                this.originDelimiters = originDelimiters;
                return reqResp;
            }
        }
        return null;
    }


    public ArrayList<String> detectKeyDelimiters(HttpRequestResponse baseReqResp, List<String> delimiters){
        ArrayList<String> out = new ArrayList<>();
        if (baseReqResp.request().path().contains("?")) return null;
        if (!baseReqResp.hasResponse() || baseReqResp.response().statusCode()==0 ) return null;

        int cacheCount = isCachedResponse(baseReqResp);
        if (cacheCount==0) return null;

        for (String delim : delimiters) {
            HttpRequestResponse testReqResp = api.http().sendRequest(baseReqResp.request().withPath(baseReqResp.request().path() + delim + randomNonce(9)));
            if (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp)) {
                out.add(delim);
            }
        }
        this.keyDelimiters = out;
        return out;
    }

    public HttpRequestResponse detectKeyDelimiters(List<String> delimiters){
        for (HttpRequestResponse reqResp : this.staticReqs){
            HttpRequestResponse testReqResp = api.http().sendRequest(reqResp.request());
            List<String> keyDelimiters = detectKeyDelimiters(testReqResp, delimiters);
            if (keyDelimiters != null) {
                this.keyDelimiters = keyDelimiters;
                return reqResp;
            }
        }
        return null;
    }

    public static boolean[] detectOriginNormalization(HttpRequest request){
        if (request.pathWithoutQuery().length()<=1 || !stripSlash(request.pathWithoutQuery().substring(1)).contains("/")) return null;
        boolean[] out = new boolean[10];
        HttpRequestResponse testReqResp;
        HttpRequestResponse baseReqResp = api.http().sendRequest(request);
        if (!baseReqResp.hasResponse() || baseReqResp.response().statusCode()==0 || baseReqResp.response().statusCode()>300) return null;
        HttpRequestResponse notfound = api.http().sendRequest(request.withPath("/aaa/bb/"+request.path()));
        if (!notfound.hasResponse() || notfound.response().statusCode()==0) return null;
        if (baseReqResp.response().statusCode() == notfound.response().statusCode()) return null;

        testReqResp = api.http().sendRequest(request.withPath("/."+request.path()));
        out[SINGLE_DOT] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 5);

        testReqResp = api.http().sendRequest(request.withPath("/aaa/.."+request.path()));
        out[DOT_SEGMENT] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 10);

        testReqResp = api.http().sendRequest(request.withPath("/aaa\\.."+request.path()));
        out[BACKSLASH_DOT_SEGMENT] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 10);

        testReqResp = api.http().sendRequest(request.withPath("///"+request.path()));
        out[MULTI_SLASH] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 5);

        testReqResp = api.http().sendRequest(request.withPath("/"+request.path().substring(1).replace("/", "\\")));
        out[BACK_SLASH] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 5);

        testReqResp = api.http().sendRequest(request.withPath("/"+request.path().substring(1).replace("/", "%2f")));
        out[ENCODED_SLASH] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 5);

        testReqResp = api.http().sendRequest(request.withPath("/"+request.path().substring(1).replace("/", "%5c")));
        out[ENCODED_BACKSLASH] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 5);

        testReqResp = api.http().sendRequest(request.withPath("/aaa%2f.."+request.path()));
        out[ENCODED_SEGMENT] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 15);

        testReqResp = api.http().sendRequest(request.withPath("/aaa%5c.."+request.path()));
        out[ENCODED_BACK_SEGMENT] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 15);

        testReqResp = api.http().sendRequest(request.withPath("/"+URLencode(request.path().substring(1))));
        out[PATH_DECODING] = (testReqResp.hasResponse() && baseReqResp.response().statusCode() == testReqResp.response().statusCode() && Math.abs(baseReqResp.response().body().length() - testReqResp.response().body().length()) < 5);

        return out;
    }

    public HttpRequestResponse detectOriginNormalization(){
        for (HttpRequestResponse reqResp : this.dynamicReqs){
            boolean[] originNormalization = detectOriginNormalization(reqResp.request());
            if (originNormalization != null) {
                this.originNormalization = originNormalization;
                return reqResp;
            }
        }
        return null;
    }

    public boolean[] getOriginNormalization(){
        return this.originNormalization;
    }

    public static boolean[] detectKeyNormalization(HttpRequest request){
        //A cached request/response MUST be used in this function
        //to detect the different normalization behaviours and obtain consistent results, the base request MUST at least contain a path with multi directory levels: /dir1/file

        if (request.pathWithoutQuery().length()<=1 || !stripSlash(request.pathWithoutQuery().substring(1)).contains("/")) return null;
        boolean[] out = new boolean[11];
        HttpRequestResponse testReqResp;
        HttpRequestResponse baseReqResp = api.http().sendRequest(request);
        if (!baseReqResp.hasResponse() || baseReqResp.response().statusCode()==0 ) return null;

        int cacheCount = isCachedResponse(baseReqResp);
        if (cacheCount==0) return null;

        testReqResp = api.http().sendRequest(request.withPath("/."+request.path()));
        out[SINGLE_DOT] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath("/aaa/.."+request.path()));
        out[DOT_SEGMENT] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath("/aaa\\.."+request.path()));
        out[BACKSLASH_DOT_SEGMENT] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath("///"+request.path()));
        out[MULTI_SLASH] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath("/"+request.path().substring(1).replace("/", "\\")));
        out[BACK_SLASH] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath("/"+request.path().substring(1).replace("/", "%2f")));
        out[ENCODED_SLASH] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath("/"+request.path().substring(1).replace("/", "%5c")));
        out[ENCODED_BACKSLASH] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath("/aaa%2f.."+request.path()));
        out[ENCODED_SEGMENT] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath("/aaa%5c.."+request.path()));
        out[ENCODED_BACK_SEGMENT] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath("/"+URLencode(request.path().substring(1))));
        out[PATH_DECODING] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        testReqResp = api.http().sendRequest(request.withPath(addCacheBuster(request)));
        out[IS_QUERY_KEYED] = (testReqResp.hasResponse() && compareResp(baseReqResp.response(), testReqResp.response()) && cacheCount == getCacheHits(testReqResp));

        return out;
    }

    public HttpRequestResponse detectKeyNormalization(){
        for (HttpRequestResponse reqResp : this.staticReqs){
            api.http().sendRequest(reqResp.request());
            boolean[] keyNormalization = detectKeyNormalization(reqResp.request());
            if (keyNormalization != null) {
                this.keyNormalization = keyNormalization;
                return reqResp;
            }
        }
        return null;
    }

    public boolean[] getKeyNormalization(){
        return this.keyNormalization;
    }

    public void addRequestResponse(HttpRequestResponse reqResp){
        if (isStatic(reqResp) || isCachedResponse(reqResp)!=0){
            addStaticRequest(reqResp);
        }
        else {
            addDynamicRequest(reqResp);
        }
    }

    public void addStaticRequest(HttpRequestResponse req){
        this.staticReqs.add(req);
    }

    public void addDynamicRequest(HttpRequestResponse req){
        this.dynamicReqs.add(req);
    }

    public boolean containsRequest(HttpRequest req){
        for (HttpRequestResponse reqResp : dynamicReqs){
            if (reqResp.request().pathWithoutQuery().equals(req.pathWithoutQuery())) return true;
        }
        for (HttpRequestResponse reqResp : staticReqs){
            if (reqResp.request().pathWithoutQuery().equals(req.pathWithoutQuery())) return true;
        }
        return false;
    }


    public static int isCachedResponse(HttpRequestResponse reqResp){
        int cacheCount = getCacheHits(reqResp);
        HttpRequestResponse testReqResp = api.http().sendRequest(reqResp.request());
        while (cacheCount < getCacheHits(testReqResp)){
            cacheCount = getCacheHits(testReqResp);
            testReqResp = api.http().sendRequest(testReqResp.request());
        }
        return cacheCount;
    }

    public static int getCacheHits(HttpRequestResponse reqResp){
        int cacheHeader = 0;
        for (HttpHeader hdr : reqResp.response().headers()){
            String name = hdr.name().toLowerCase();
            String value = hdr.value().toLowerCase();
            if (name.contains("cache") || name.contains("server-timing")){
                cacheHeader+= countOccurrences(value, "hit");
            }
            if (name.equals("age") && Integer.parseInt(value)>0) cacheHeader++;
        }
        return cacheHeader;
    }

    public static int countOccurrences(String str, String subStr) {
        if (str == null || subStr == null || subStr.isEmpty()) {
            return 0;
        }
        int count = 0;
        int index = 0;
        while ((index = str.indexOf(subStr, index)) != -1) {
            count++;
            index += subStr.length();
        }
        return count;
    }

    public static String getNetworkHash(HttpRequest request){
        HttpRequestResponse baseReqResp = api.http().sendRequest(request);
        HttpRequestResponse testReqResp;
        if (!baseReqResp.hasResponse() || baseReqResp.response().statusCode() >= 400) return null;

        StringBuilder signature = new StringBuilder();

        for (String badChar : BAD_CHARS){
            testReqResp = api.http().sendRequest(request.withPath(request.pathWithoutQuery()+badChar+"XX"+randomNonce(9)));
            signature.append(getResponseSignature(testReqResp));
            /*testReqResp = api.http().sendRequest(request.withHeader("X-Header", "abc"+badChar+"cde"));
            signature.append(getResponseSignature(testReqResp));*/
        }

        return calculateMD5(signature.toString());
    }

    public static String getNetworkHash(HttpRequestResponse reqResp){
        return getNetworkHash(reqResp, false);
    }

    public static String getNetworkHash(HttpRequestResponse reqResp, boolean fullDetection){
        if (fullDetection){
            return getNetworkHash(reqResp.request());
        }
        else {
            return calculateMD5(getResponseSignature(reqResp));
        }
    }


    public static String getResponseSignature(HttpRequestResponse baseReqResp){
        if (!baseReqResp.hasResponse()) return "NULLRESP";
        if (baseReqResp.response().statusCode() == 0) return "SC:0";
        StringBuilder out = new StringBuilder();
        out.append("SC:").append(baseReqResp.response().statusCode());
        out.append("server:");
        if (baseReqResp.response().hasHeader("server")) out.append(baseReqResp.response().header("server").value());
        else out.append("NULL");

        out.append("X-Powered:");
        if (baseReqResp.response().hasHeader("x-powered-by")) out.append(baseReqResp.response().header("x-powered-by").value());
        else out.append("NULL");

        out.append("VIA:");
        if (baseReqResp.response().hasHeader("via")) out.append(baseReqResp.response().header("via").value());
        else out.append("NULL");

        out.append("X-FF:");
        if (baseReqResp.response().hasHeader("x-forwarded-for")) out.append(baseReqResp.response().header("x-forwarded-for").value());
        else out.append("NULL");

        out.append("X-SB:");
        if (baseReqResp.response().hasHeader("x-served-by")) out.append(baseReqResp.response().header("x-served-by").value());
        else out.append("NULL");

        String headers = baseReqResp.response().headers().toString().toLowerCase();

        out.append("KW:");
        for (String key : SERVER_KEYWORDS){
            if (headers.contains(key)) out.append("-").append(key);
        }

        return out.toString();
    }


    public static String calculateMD5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input.getBytes());
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not found", e);
        }
    }


    public static boolean isStatic(HttpRequest request){
        return request.pathWithoutQuery().lastIndexOf(".") > 0 && STATIC_EXTENSIONS.contains(request.pathWithoutQuery().substring(request.pathWithoutQuery().lastIndexOf(".") + 1).toUpperCase());
    }

    public static boolean isStatic(HttpRequestResponse reqResp){
        if (!(reqResp.request().method().equals("GET") || reqResp.request().method().equals("HEAD") || reqResp.request().method().equals("OPTIONS"))) return false;
        if (isStatic(reqResp.request())) return true;
        return reqResp.hasResponse() && reqResp.response().statusCode() != 0 && reqResp.response().mimeType().equals(MimeType.CSS) || reqResp.response().mimeType().equals(MimeType.FONT_WOFF) || reqResp.response().mimeType().equals(MimeType.FONT_WOFF2) || reqResp.response().mimeType().equals(MimeType.IMAGE_BMP) || reqResp.response().mimeType().equals(MimeType.IMAGE_GIF) || reqResp.response().mimeType().equals(MimeType.IMAGE_JPEG) || reqResp.response().mimeType().equals(MimeType.IMAGE_PNG) || reqResp.response().mimeType().equals(MimeType.SCRIPT) || reqResp.response().mimeType().equals(MimeType.APPLICATION_FLASH);
    }

    public static boolean compareResp(HttpResponse r1, HttpResponse r2){
        return  (r1 != null && r2 != null && r1.statusCode() != 0 && r1.statusCode() == r2.statusCode() && (Math.abs(r1.body().length()-r2.body().length())<10) && compareHeader(r1, r2, "content-type") && compareHeader(r1, r2, "server") && compareHeader(r1, r2, "vary") && compareHeader(r1,r2,"location"));
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

    public static String getQuery(HttpRequest base){
        if (!base.path().contains("?")) return "";
        return base.path().substring(base.path().indexOf("?"));
    }

    public static String URLencode(String input) {
        StringBuilder result = new StringBuilder();
        for (char ch : input.toCharArray()) {
            if (ch == '?' || ch == '/') {
                result.append(ch);
            } else {
                String encodedChar = String.format("%%%02X", (int) ch);
                result.append(encodedChar);
            }
        }
        return result.toString();
    }

    public static String stripSlash(String path){
        if (path.length()>1 && path.endsWith("/")) return path.substring(0,path.length()-1);
        return path;
    }

    public static String addCacheBuster(HttpRequest request){
        return request.path()+(getQuery(request).isEmpty() ?"?" : "&")+randomNonce(6);
    }


    public static String randomNonce(int length){
        return String.format("%09d", new Random().nextInt(1000000000));
    }

    public static String pathWithoutQuery(String base){
        if (!base.contains("?")) return base;
        return base.substring(0, base.indexOf("?"));
    }

    public static ArrayList<String> splitPathSegments(String path){
        ArrayList<String> segments = new ArrayList<>();
        StringTokenizer st = new StringTokenizer((path.contains("?") ? pathWithoutQuery(path): path),"/");
        while (st.hasMoreTokens()) {
            String dir = st.nextToken();
            if (dir.isEmpty()) continue;
            segments.add(dir);
        }
        return segments;
    }

    public static String removeLastSegment(String path){
        String out = stripSlash(path);
        return out.substring(0, out.lastIndexOf("/"));
    }

    public static HttpRequest addRequestCacheBuster(HttpRequest request){
        return request.withPath(request.path()+(getQuery(request).isEmpty() ?"?" : "&")+randomNonce(6));
    }
}
