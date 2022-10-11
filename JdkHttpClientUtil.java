package smile;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;


/*
 * 由于http/2 server push可能被移除:
 * https://groups.google.com/a/chromium.org/g/blink-dev/c/K3rYLvmQUBY/m/vOWBKZGoAQAJ?pli=1
 * https://evertpot.com/http-2-push-is-dead/
 * 因此本工具类不涉及http/2的服务器推送功能,仅摘要http/2 server push的示例代码
 *
 *
 * 本工具类参考链接:
 * java11 httpclient:https://golb.hplar.ch/2019/01/java-11-http-client.html#upload-with-multipart
 * rfc1867  https://tools.ietf.org/html/rfc1867
 * 重试以及连接池配置可查看MultiExchange,ConnectionPool类
 *  https://segmentfault.com/a/1190000016579536
 *  https://www.jianshu.com/p/40dc5f72748b
 *
 * */


/**
 * Http工具类，基于jdk17
 * 若要配置系统变量以控制Http请求,须在jdk.internal.net.http.common.Utils类加载之前配置!<br/>
 * 1.   在httpclient实例创建之前通过System.setProperty配置<br/>
 * 2.   为了确保准确,建议在jvm启动命令处配置. 配置格式: -Dkey=value
 * <br/><br/>
 * 如-Djdk.internal.httpclient.debug=true可开启debug调试
 **/
@Slf4j
public class HttpUtil {

    /**
     * 发送get请求
     *
     * @param url 请求url,可带参
     */
    public static HttpResult<String> get(String url) throws IOException, InterruptedException {
        return get(url, null);
    }

    /**
     * 发送get请求
     *
     * @param url    请求地址
     * @param params 请求参数
     */
    public static HttpResult<String> get(String url, Map<String, String> params)
            throws IOException, InterruptedException {
        return getWithGzip(url, params, null, -1, STRING_BODY_HANDLER);
    }

    /**
     * 发送get异步请求
     *
     * @param url 请求地址，可以拼接参数
     */
    public static CompletableFuture<HttpResult<String>> getAsync(String url) {
        return getAsync(url, null);
    }

    /**
     * 发送get异步请求
     *
     * @param url    请求地址
     * @param params 请求参数
     */
    public static CompletableFuture<HttpResult<String>> getAsync(String url, Map<String, String> params) {
        return getAsync(url, params, null, -1, true, STRING_BODY_HANDLER);
    }

    /**
     * 下载文件
     * <br/>
     * 若确定服务器可以响应Content-Disposition: attachment; filename=a.xx
     * 那么fileName文件名可以不传递,否则必须传递fileName
     *
     * @param url       请求路径
     * @param directory 保存的文件目录
     * @param fileName  文件名称 可以不传递
     * @param timeOut   超时时间 秒
     */
    public static HttpResult<Path> downLoad(String url, String directory, String fileName, int timeOut)
            throws IOException, InterruptedException {
        HttpResponse.BodyHandler<Path> bodyHandler;
        Path path = Path.of(directory);
        if (!Files.isDirectory(path)) {
            throw new RuntimeException("不是一个目录: " + directory);
        }
        if (fileName == null || fileName.isBlank()) {
            bodyHandler = HttpResponse.BodyHandlers.ofFileDownload(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        } else {
            bodyHandler = HttpResponse.BodyHandlers.ofFile(Path.of(directory, fileName));
        }
        return getWithoutGzip(url, null, null, timeOut, bodyHandler);
    }

    public static <T> HttpResult<T> getWithGzip(String url, Map<String, String> params, Map<String,
            String> headers, int timeOut, HttpResponse.BodyHandler<Supplier<T>> responseBodyHandler)
            throws IOException, InterruptedException {
        HttpRequest request = ofGetHttpRequest(url, params, headers, timeOut, true);
        HttpResponse<Supplier<T>> response = DEFAULT_HTTP_CLIENT.send(request, responseBodyHandler);
        return HttpResult.fromSupplier(response);
    }

    public static <T> HttpResult<T> getWithoutGzip(String url, Map<String, String> params, Map<String,
            String> headers, int timeOut, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        HttpRequest request = ofGetHttpRequest(url, params, headers, timeOut, false);
        HttpResponse<T> response = DEFAULT_HTTP_CLIENT.send(request, responseBodyHandler);
        return new HttpResult<>(response.statusCode(), response.headers(), response.body());
    }

    /**
     * 发送get异步请求
     *
     * @param url                 请求地址
     * @param params              请求参数map,无需urlEncode
     * @param headers             请求头map
     * @param timeOut             超时时间 秒
     * @param gzip                启用gzip
     * @param responseBodyHandler HttpResponse.BodyHandler
     */
    public static <T> CompletableFuture<HttpResult<T>> getAsync(String url, Map<String, String> params, Map<String,
            String> headers, int timeOut, boolean gzip, HttpResponse.BodyHandler<Supplier<T>> responseBodyHandler) {

        HttpRequest request = ofGetHttpRequest(url, params, headers, timeOut, gzip);
        return DEFAULT_HTTP_CLIENT.sendAsync(request, responseBodyHandler)
                .thenApply(HttpResult::fromSupplier);
    }

    /**
     * 构造Get请求的HttpRequest
     *
     * @param url     请求地址
     * @param params  请求参数map,无需urlEncode
     * @param headers 请求头map
     * @param timeOut 超时时间 秒
     * @param gzip    启用gzip
     * @return get请求的HttpRequest
     */
    private static HttpRequest ofGetHttpRequest(String url, Map<String, String> params, Map<String, String> headers,
                                                int timeOut, boolean gzip) {
        Map<String, String> pMap = Optional.ofNullable(params)
                // 改为HashMap,防止外部传入的是一个不可变Map
                .map(HashMap::new)
                .orElse(new HashMap<>());
        String urlPrefix = Optional.of(url)
                .map(String::strip)
                .map(s -> s.split("\\?"))
                .map(strings -> {
                    if (strings.length > 2) {
                        throw new RuntimeException("url中存在多个?:" + url);
                    }
                    if (strings.length == 2) {
                        String paramStr = strings[1];
                        if (paramStr.contains("=")) {
                            Arrays.stream(paramStr.split("&"))
                                    .map(s -> s.split("="))
                                    .forEach(arr -> {
                                        int length = arr.length;
                                        String v;
                                        if (length == 1) {
                                            v = "";
                                        } else if (length == 2) {
                                            v = arr[1];
                                        } else {
                                            throw new RuntimeException("解析错误:" + paramStr);
                                        }
                                        pMap.put(arr[0], v);
                                    });
                        } else {
                            // 存在没有=的情况,一般用作特殊用途,添加=反而会有问题
                            // 此时params的Map正常情况是不需要传递参数的
                            strings[1] = URLEncoder.encode(paramStr, StandardCharsets.UTF_8);
                            return String.join("?", strings);
                        }
                    }
                    return strings[0];
                })
                .orElseThrow();

        String urlWithParam = Optional.of(pMap)
                .filter(m -> !m.isEmpty())
                .map(m -> m.entrySet()
                        .stream()
                        .map(entry -> {
                            String value = Optional.ofNullable(entry.getValue())
                                    .map(s -> URLEncoder.encode(s, StandardCharsets.UTF_8))
                                    .orElse("");
                            return String.join("=", URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8), value);
                        })
                        .collect(Collectors.joining("&", urlPrefix + "?", "")))
                .orElse(urlPrefix);
        return ofHttpRequestBuilder(urlWithParam, headers, timeOut, gzip).build();
    }


    /**
     * 以json形式发送post请求
     * Content-Type:application/json;charset=utf-8
     *
     * @param url  请求地址
     * @param json json数据 可以为null
     */
    public static HttpResult<String> postJson(String url, String json) throws IOException, InterruptedException {
        return post(url, null, json, null, null, -1, true, STRING_BODY_HANDLER);
    }

    /**
     * 以json形式发送post异步请求
     * Content-Type:application/json;charset=utf-8
     *
     * @param url  请求地址
     * @param json json数据 可以为null
     */
    public static CompletableFuture<HttpResult<String>> postJsonAsync(String url, String json) {
        return postAsync(url, null, json, null, null, -1, true, STRING_BODY_HANDLER);
    }

    /**
     * 以普通表单提交的方式发送post请求
     * Content-Type: application/x-www-form-urlencoded;charset=utf-8
     *
     * @param url     请求地址
     * @param formMap map参数
     */
    public static HttpResult<String> postFormData(String url, Map<String, String> formMap) throws IOException, InterruptedException {
        return post(url, formMap, null, null, null, -1, true, STRING_BODY_HANDLER);
    }

    /**
     * 以普通表单提交的方式发送post异步请求
     * Content-Type: application/x-www-form-urlencoded;charset=utf-8
     *
     * @param url     请求地址
     * @param formMap map参数
     */
    public static CompletableFuture<HttpResult<String>> postFormDataAsync(String url, Map<String, String> formMap) {
        return postAsync(url, formMap, null, null, null, -1, true, STRING_BODY_HANDLER);
    }

    /**
     * multipart/form-data方式提交表单
     *
     * @param url 请求地址
     * @param map map的key为字段名; value:若是文件为Path类型,若为普通字段是基本类型
     */
    public static HttpResult<String> postMultipart(String url, Map<String, Object> map) throws IOException, InterruptedException {
        return postMultipart(url, map, -1);
    }

    /**
     * multipart/form-data方式提交表单
     *
     * @param url     请求地址
     * @param map     map的key为字段名; value:若是文件为Path类型,若为普通字段是基本类型
     * @param timeOut 超时时间 秒
     */
    public static HttpResult<String> postMultipart(String url, Map<String, Object> map, int timeOut) throws IOException,
            InterruptedException {
        return post(url, null, null, map, null, timeOut, true, STRING_BODY_HANDLER);
    }

    /**
     * multipart/form-data方式异步提交表单
     *
     * @param url     请求地址
     * @param map     map的key为字段名; value:若是文件为Path类型,若为普通字段是基本类型
     * @param timeOut 超时时间 秒
     */
    public static CompletableFuture<HttpResult<String>> postMultipartAsync(String url, Map<String, Object> map, int timeOut) {
        return postAsync(url, null, null, map, null, timeOut, true, STRING_BODY_HANDLER);
    }

    /**
     * 发送post请求
     *
     * @param url                 请求地址
     * @param formDataMap         提交form表单数据时设置
     * @param json                发送json数据时设置
     * @param multipartMap        上传类型的表单数据  map的key为字段名 若是文件 map的value为Path类型 若为普通字段 value可以是基本类型
     * @param headers             请求头map
     * @param timeOut             超时时间 秒
     * @param gzip                启用gzip
     * @param responseBodyHandler responseBodyHandler
     */
    public static <T> HttpResult<T>
    post(String url, Map<String, String> formDataMap, String json, Map<String, Object> multipartMap, Map<String, String> headers,
         int timeOut, boolean gzip, HttpResponse.BodyHandler<Supplier<T>> responseBodyHandler) throws IOException, InterruptedException {
        HttpRequest request = ofPostHttpRequest(url, formDataMap, json, multipartMap, headers, timeOut, gzip);
        HttpResponse<Supplier<T>> response = DEFAULT_HTTP_CLIENT.send(request, responseBodyHandler);
        return HttpResult.fromSupplier(response);
    }

    /**
     * 发送post异步请求
     *
     * @param url                 请求地址
     * @param formDataMap         提交form表单数据时设置
     * @param json                发送json数据时设置
     * @param multipartMap        上传类型的表单数据  map的key为字段名 若是文件 map的value为Path类型 若为普通字段 value可以是基本类型
     * @param headers             请求头map
     * @param timeOut             超时时间 秒
     * @param gzip                启用gzip
     * @param responseBodyHandler responseBodyHandler
     */
    public static <T> CompletableFuture<HttpResult<T>>
    postAsync(String url, Map<String, String> formDataMap, String json, Map<String, Object> multipartMap, Map<String, String> headers,
              int timeOut, boolean gzip, HttpResponse.BodyHandler<Supplier<T>> responseBodyHandler) {
        HttpRequest request = ofPostHttpRequest(url, formDataMap, json, multipartMap, headers, timeOut, gzip);
        return DEFAULT_HTTP_CLIENT.sendAsync(request, responseBodyHandler).thenApply(HttpResult::fromSupplier);
    }

    /**
     * 从ContentType值中解析出Charset
     * 若ContentType值中无charset 则返回UTF_8
     */
    private static Charset charsetFromContentTypeValue(String contentTypeValue) {
        // 参考自HttpResponse.BodyHandlers.ofString()
        return Optional.ofNullable(contentTypeValue)
                .map(s -> s.split(";"))
                .flatMap(strings -> Arrays.stream(strings).filter(s -> s.toLowerCase().contains("charset")).findFirst())
                .map(s -> s.split("="))
                .filter(strings -> strings.length == 2)
                .map(strings -> Charset.forName(strings[1].strip()))
                .orElse(StandardCharsets.UTF_8);
    }

    private static HttpRequest ofPostHttpRequest(String url, Map<String, String> formDataMap, String json, Map<String, Object> multipartMap,
                                                 Map<String, String> headers, int timeOut, boolean gzip) {
        boolean formDataMapNotNull = formDataMap != null && !formDataMap.isEmpty();
        boolean jsonNotNull = json != null && !json.isBlank();
        boolean multipartMapNotNull = multipartMap != null && !multipartMap.isEmpty();

        long count = Stream.of(formDataMapNotNull, jsonNotNull, multipartMapNotNull)
                .filter(Boolean::booleanValue)
                .count();
        if (count > 1) {
            throw new RuntimeException("发送post请求时,无法判断要发送哪种请求类型!");
        }

        TreeMap<String, String> headerTreeMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            headerTreeMap.putAll(headers);
        }
        Optional<String> ContentTypeValueOptional = Optional.ofNullable(headerTreeMap.get(CONTENT_TYPE))
                .filter(Predicate.not(String::isBlank));
        String contentTypeValue = ContentTypeValueOptional.orElse("application/json; charset=UTF-8");
        HttpRequest.BodyPublisher bodyPublisher;
        if (count == 0) {
            // 可以没有body
            bodyPublisher = HttpRequest.BodyPublishers.noBody();
        } else {
            if (jsonNotNull) {
                Charset charset = charsetFromContentTypeValue(contentTypeValue);
                bodyPublisher = HttpRequest.BodyPublishers.ofString(json, charset);
            } else if (formDataMapNotNull) {
                contentTypeValue = ContentTypeValueOptional.orElse("application/x-www-form-urlencoded; charset=UTF-8");
                bodyPublisher = HttpRequest.BodyPublishers.ofString(mapToQueryString(formDataMap));
            } else if (multipartMapNotNull) {
                String boundary = BOUNDARY_PREFIX + UUID.randomUUID().toString().replace("-", "");
                contentTypeValue = "multipart/form-data; boundary=" + boundary;
                bodyPublisher = ofMimeMultipartBodyPublisher(multipartMap, boundary);
            } else {
                throw new RuntimeException("不支持的类型");
            }
        }
        headerTreeMap.put(CONTENT_TYPE, contentTypeValue);
        HttpRequest.Builder builder = ofHttpRequestBuilder(url, headerTreeMap, timeOut, gzip);
        return builder.POST(bodyPublisher).build();
    }

    /**
     * webSocket
     *
     * @param url      url地址
     * @param headers  打开握手时发送的额外请求header(例如服务器设置了webSocket的路径访问也需要用户已登陆,这里可传递用户token),
     *                 注意不能传递<a href="https://tools.ietf.org/html/rfc6455#section-11.3">WebSocket协议</a>中已定义的header
     * @param listener WebSocket的接收接口
     */
    public static CompletableFuture<WebSocket> webSocket(String url, Map<String, String> headers, WebSocket.Listener listener) {
        WebSocket.Builder builder = DEFAULT_HTTP_CLIENT.newWebSocketBuilder()
                .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECOND));
        if (headers != null) {
            headers.forEach(builder::header);
        }
        return builder.buildAsync(URI.create(url), listener);
    }


    /**
     * 获取HttpRequest.Builder
     *
     * @param url     请求地址
     * @param headers 请求头map
     * @param timeOut 超时时间,秒
     * @param gzip    启用gzip
     */
    private static HttpRequest.Builder ofHttpRequestBuilder(String url, Map<String, String> headers, int timeOut, boolean gzip) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url));
        TreeMap<String, String> headerTreeMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            headerTreeMap.putAll(headers);
        }
        if (gzip) {
            headerTreeMap.put(ACCEPT_ENCODING, GZIP);
        }
        headerTreeMap.forEach(builder::setHeader);
        builder.timeout(Duration.ofSeconds(timeOut > 0 ? timeOut : REQUEST_TIMEOUT_SECOND));
        return builder;
    }


    /**
     * 参数map转请求字符串
     * 若map为null返回 空字符串""
     *
     * @param params 参数map
     */
    private static String mapToQueryString(Map<String, String> params) {
        return Optional.ofNullable(params)
                .map(m -> m.entrySet()
                        .stream()
                        .map(entry -> {
                            String value = Optional.ofNullable(entry.getValue())
                                    .map(s -> URLEncoder.encode(s, StandardCharsets.UTF_8))
                                    .orElse("");
                            return String.join("=", entry.getKey(), value);
                        })
                        .collect(Collectors.joining("&")))
                .orElse("");
    }

    /**
     * 根据map boundary 构造mimeMultipartBodyPublisher
     *
     * @param map      map的key为字段名; value:若是文件为Path类型,若为普通字段是基本类型
     * @param boundary 边界
     */
    private static HttpRequest.BodyPublisher ofMimeMultipartBodyPublisher(Map<String, Object> map, String boundary) {
        byte[] separator = ("--" + boundary + "\r\nContent-Disposition: form-data; name=").getBytes(StandardCharsets.UTF_8);
        List<byte[]> byteArrays = map.entrySet()
                .stream()
                .flatMap(entry -> {
                    String k = entry.getKey();
                    Object v = entry.getValue();

                    if (v instanceof Path path) {
                        String mimeType;
                        try {
                            mimeType = Files.probeContentType(path);
                        } catch (IOException e) {
                            throw new UncheckedIOException(e);
                        }
                        mimeType = mimeType == null || mimeType.isBlank() ? "application/octet-stream" : mimeType;
                        byte[] fileInfoArr = ("\"" + k + "\"; filename=\"" + path.getFileName()
                                + "\"\r\nContent-Type: " + mimeType + "\r\n\r\n").getBytes(StandardCharsets.UTF_8);
                        byte[] fileArr;
                        try {
                            fileArr = Files.readAllBytes(path);
                        } catch (IOException e) {
                            throw new UncheckedIOException(e);
                        }
                        return Stream.of(separator, fileInfoArr, fileArr, "\r\n".getBytes(StandardCharsets.UTF_8));
                    } else {
                        return Stream.of(separator, ("\"" + k + "\"\r\n\r\n" + v + "\r\n").getBytes(StandardCharsets.UTF_8));
                    }
                })
                .collect(Collectors.toList());
        byteArrays.add(("--" + boundary + "--").getBytes(StandardCharsets.UTF_8));
        return HttpRequest.BodyPublishers.ofByteArrays(byteArrays);
    }

    /*
     * 静态成员变量
     */
    private static final long CONNECT_TIMEOUT_SECOND = 5;
    private static final long REQUEST_TIMEOUT_SECOND = 10;

    private static final String CONTENT_TYPE = "Content-Type";
    private static final String ACCEPT_ENCODING = "Accept-Encoding";
    private static final String CONTENT_ENCODING = "Content-Encoding";
    private static final String GZIP = "gzip";
    private static final String BOUNDARY_PREFIX = "----JavaHttpClientBoundary";

    // 默认配置满足使用. 具体可查看源码，例如线程池(用于异步处理)，连接池等
    private static final HttpClient DEFAULT_HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECOND))
            // 版本 默认http2,不支持会自动降级
//            .version(HttpClient.Version.HTTP_1_1)
            // 设置支持不安全的https
            //　.sslContext(ofUnsafeSslContext())
            // 重定向
            // .followRedirects(HttpClient.Redirect.NEVER)
            // .cookieHandler(CookieHandler.getDefault())
            // 代理
            // .proxy(ProxySelector.of(new InetSocketAddress("proxy.example.com", 80)))
            // 验证
            // .authenticator(Authenticator.getDefault())
            .build();

    /*
     * 关于错误的https证书:
     * 注意:在正常部署中，不希望使用下列机制中的任何一种，因为正常情况下应该可以自动验证任何正确配置的HTTPS服务器提供的证书
     *
     * 对于https证书错误,但是又想httpClient忽略证书错误正常执行,可以有下面几种解决办法:
     *   1. 构建一个SSLContext来忽略错误的证书,并且在初始化HttpClient客户端的时候传递进去.
     *       这样的问题在于,对于所有网址完全禁用了服务器身份验证
     *   2. 若不想采用上述办法,并且只有错误的证书比较少,比如一个,则可以使用以下命令将其导入密钥库
     *          keytool -importcert -keystore keystorename -storepass pass -alias cert -file certfile
     *      然后使用InputStream初始化SSLContext，如下所示读取密钥库：
     *          char[] passphrase = ..
     *          KeyStore ks = KeyStore.getInstance("PKCS12");
     *          ks.load(i, passphrase); // i is an InputStream reading the keystore
     *
     *          KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
     *          kmf.init(ks, passphrase);
     *
     *          TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
     *          tmf.init(ks);
     *
     *          sslContext = SSLContext.getInstance("TLS");
     *          sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
     *  3.  以上两种解决方案均适用于自签名证书。
     *      第三种选择是服务器提供有效的，非自签名的证书.但对于与它提供的证书中的任何名称都不匹配的host，
     *      则使用系统属性“ jdk.internal.httpclient.disableHostnameVerification”设置为“ true”，
     *      这将强制以以前使用HostnameVerifier API的相同方式来接受证书
     * */

    /**
     * 创建不安全的SSLContext,这将对于所有网址完全禁用了服务器身份验证
     */
    private static SSLContext ofUnsafeSslContext() {
        /*
         * jdk.internal.httpclient.disableHostnameVerification 是用来控制是否禁用主机名验证的
         * 查看源码可知
         *  1.AbstractAsyncSSLConnection的静态成员变量disableHostnameVerification类加载的时候从
         *      Util类的isHostnameVerificationDisabled()方法,而此方法是在Util类加载的时候从系统变量
         *      jdk.internal.httpclient.disableHostnameVerification读取而来
         *  2.AbstractAsyncSSLConnection的构造方法中调用了本类的createSSLParameters方法
         *      在此方法中,先从我们构建的httpClient中取出SSLParameters拷贝一份,若disableHostnameVerification为false
         *      则sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
         *
         * 注意:测试环境下使用自己造的证书,若主机名和证书不一样,需要配置此参数
         */
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        TrustManager[] trustAllCertificates = new TrustManager[]{new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] arg0, String arg1) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] arg0, String arg1) {
            }
        }};
        SSLContext unsafeSslContext;
        try {
            unsafeSslContext = SSLContext.getInstance("TLS");
            unsafeSslContext.init(null, trustAllCertificates, new SecureRandom());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException("构造unsafeSslContext出现异常", e);
        }
        return unsafeSslContext;
    }

    /**
     * 处理了gzip情况的String BodyHandler
     */
    private static final HttpResponse.BodyHandler<Supplier<String>> STRING_BODY_HANDLER = gzipBodyHandler(String::new);

    /**
     * 处理gzip压缩的BodyHandler
     * <br/><br/>
     * 注意:即使本httpClient请求头携带了Accept-Encoding: gzip头信息,服务器也可能不返回Content-Encoding: gzip头信息
     * <br/>
     * 这是因为:
     * <br/>
     * 1.服务器不支持或者没有开启gzip
     * <br/>
     * 2.有些服务器对本httpClient发送的请求就不响应Content-Encoding,但对浏览器却响应Content-Encoding
     * <br/>
     * 因此如果要测试gzip 建议访问github.com,经测试此网址用本httpClient访问可以返回Content-Encoding: gzip
     */
    private static <T> HttpResponse.BodyHandler<Supplier<T>> gzipBodyHandler(BiFunction<byte[], Charset, T> function) {
        return responseInfo -> {
            Map<String, List<String>> headerMap = responseInfo.headers().map()
                    .entrySet()
                    .stream()
                    .collect(Collectors.toMap(Map.Entry::getKey,
                            entry -> entry.getValue().stream().map(String::toLowerCase).toList(),
                            (strings, strings2) -> strings,
                            () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER)
                    ));
            Charset charset = headerMap.getOrDefault(CONTENT_TYPE, List.of("text/html; charset=utf-8"))
                    .stream()
                    .findFirst()
                    .map(HttpUtil::charsetFromContentTypeValue)
                    .orElseThrow();
            return HttpResponse.BodySubscribers.mapping(HttpResponse.BodySubscribers.ofByteArray(),
                    byteArray -> () -> {
                        boolean isGzip = headerMap.getOrDefault(CONTENT_ENCODING, List.of()).contains(GZIP);
                        if (isGzip) {
                            try (ByteArrayOutputStream os = new ByteArrayOutputStream();
                                 InputStream is = new GZIPInputStream(new ByteArrayInputStream(byteArray))) {
                                is.transferTo(os);
                                // os.toByteArray()存在复制
                                return function.apply(os.toByteArray(), charset);
                            } catch (IOException e) {
                                throw new UncheckedIOException(e);
                            }
                        } else {
                            return function.apply(byteArray, charset);
                        }
                    });
        };
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class HttpResult<T> {
        private int statusCode;
        private HttpHeaders httpHeaders;
        private T body;

        public static <T> HttpResult<T> fromSupplier(HttpResponse<Supplier<T>> httpResponse) {
            return new HttpResult<>(httpResponse.statusCode(), httpResponse.headers(), httpResponse.body().get());
        }
    }

}
