package org.joget.marketplace.spsaml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Sends email through the Microsoft Graph sendMail API using the OAuth 2.0
 * client credentials grant (application permission Mail.Send).
 */
public class GraphMailSender {

    public static final String DEFAULT_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token";
    public static final String DEFAULT_SCOPE = "https://graph.microsoft.com/.default";
    public static final String DEFAULT_SEND_MAIL_URL = "https://graph.microsoft.com/v1.0/users/{from}/sendMail";

    private static final int MAX_ATTEMPTS = 3;
    private static final long MAX_RETRY_WAIT_MS = 60000;
    private static final long EXPIRY_SKEW_MS = 60000;
    private static final Map<String, CachedToken> TOKENS = new ConcurrentHashMap<String, CachedToken>();

    private final String tenantId;
    private final String clientId;
    private final String clientSecret;
    private final String tokenUrl;
    private final String scope;
    private final String sendMailUrl;

    public GraphMailSender(String tenantId, String clientId, String clientSecret, String tokenUrl, String scope, String sendMailUrl) {
        this.tenantId = trim(tenantId);
        this.clientId = trim(clientId);
        this.clientSecret = clientSecret == null ? "" : clientSecret;
        this.tokenUrl = trim(tokenUrl).isEmpty() ? DEFAULT_TOKEN_URL : trim(tokenUrl);
        this.scope = trim(scope).isEmpty() ? DEFAULT_SCOPE : trim(scope);
        this.sendMailUrl = trim(sendMailUrl).isEmpty() ? DEFAULT_SEND_MAIL_URL : trim(sendMailUrl);
    }

    public boolean isConfigured() {
        return !tenantId.isEmpty() && !clientId.isEmpty() && !clientSecret.isEmpty();
    }

    public void send(String from, Collection<String> to, Collection<String> cc, String subject, String body, boolean html) throws IOException {
        if (!isConfigured()) {
            throw new IOException("Microsoft Graph tenant ID, client ID and client secret are required");
        }
        if (trim(from).isEmpty() && usesFromPlaceholder()) {
            throw new IOException("From email address is required for Microsoft Graph");
        }
        if (to == null || to.isEmpty()) {
            throw new IOException("No email recipient specified");
        }

        JSONObject message = new JSONObject();
        message.put("subject", subject == null ? "" : subject);
        JSONObject content = new JSONObject();
        content.put("contentType", html ? "HTML" : "Text");
        content.put("content", body == null ? "" : body);
        message.put("body", content);
        message.put("toRecipients", recipients(to));
        if (cc != null && !cc.isEmpty()) {
            message.put("ccRecipients", recipients(cc));
        }
        JSONObject payload = new JSONObject();
        payload.put("message", message);
        byte[] data = payload.toString().getBytes(StandardCharsets.UTF_8);

        String url = resolveSendMailUrl(trim(from));
        boolean tokenRefreshed = false;
        for (int attempt = 1; ; attempt++) {
            HttpResponse response = post(url, "application/json", "Bearer " + getAccessToken(), data);
            if (response.status >= 200 && response.status < 300) {
                return;
            }
            // An expired or revoked cached token gets one fresh retry.
            if (response.status == 401 && !tokenRefreshed) {
                TOKENS.remove(cacheKey());
                tokenRefreshed = true;
                continue;
            }
            boolean retryable = response.status == 429 || response.status >= 500;
            if (!retryable || attempt >= MAX_ATTEMPTS) {
                throw new IOException("Microsoft Graph sendMail failed, status=" + response.status + ", body=" + response.body);
            }
            sleep(retryWait(response.retryAfter, attempt));
        }
    }

    protected String getAccessToken() throws IOException {
        String key = cacheKey();
        CachedToken cached = TOKENS.get(key);
        if (cached != null && cached.expiresAt > System.currentTimeMillis() + EXPIRY_SKEW_MS) {
            return cached.accessToken;
        }

        String form = "grant_type=client_credentials"
                + "&client_id=" + encode(clientId)
                + "&client_secret=" + encode(clientSecret)
                + "&scope=" + encode(scope);
        String url = tokenUrl.replace("{tenant}", encode(tenantId));
        HttpResponse response = post(url, "application/x-www-form-urlencoded", null, form.getBytes(StandardCharsets.UTF_8));
        if (response.status < 200 || response.status >= 300) {
            throw new IOException("Microsoft Graph token request failed, status=" + response.status + ", body=" + response.body);
        }
        JSONObject token = new JSONObject(response.body);
        String accessToken = token.optString("access_token");
        if (accessToken.isEmpty()) {
            throw new IOException("Microsoft Graph token response did not contain an access token");
        }
        long expiresIn = Math.max(1, token.optLong("expires_in", 3600));
        TOKENS.put(key, new CachedToken(accessToken, System.currentTimeMillis() + expiresIn * 1000));
        return accessToken;
    }

    protected HttpResponse post(String url, String contentType, String authorization, byte[] data) throws IOException {
        if (!url.toLowerCase().startsWith("https://")) {
            throw new IOException("Microsoft Graph endpoints must use HTTPS: " + url);
        }
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        try {
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(30000);
            connection.setReadTimeout(60000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", contentType);
            if (authorization != null) {
                connection.setRequestProperty("Authorization", authorization);
            }
            OutputStream out = connection.getOutputStream();
            try {
                out.write(data);
            } finally {
                out.close();
            }
            int status = connection.getResponseCode();
            InputStream in = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            return new HttpResponse(status, read(in), connection.getHeaderField("Retry-After"));
        } finally {
            connection.disconnect();
        }
    }

    public boolean usesFromPlaceholder() {
        return sendMailUrl.contains("{from}") || sendMailUrl.contains("{SENDER_EMAIL}");
    }

    String resolveSendMailUrl(String from) throws IOException {
        // Keep '@' readable in the path; Graph accepts the UPN as-is.
        String encoded = encode(from).replace("%40", "@");
        return sendMailUrl.replace("{SENDER_EMAIL}", encoded).replace("{from}", encoded);
    }

    static long retryWait(String retryAfter, int attempt) {
        try {
            if (retryAfter != null && !retryAfter.trim().isEmpty()) {
                return Math.min(MAX_RETRY_WAIT_MS, Math.max(0, Long.parseLong(retryAfter.trim()) * 1000));
            }
        } catch (NumberFormatException e) {
            // Retry-After may be an HTTP date; fall back to backoff.
        }
        return Math.min(MAX_RETRY_WAIT_MS, 2000L * attempt);
    }

    private String cacheKey() {
        return tenantId + "|" + clientId + "|" + tokenUrl + "|" + scope;
    }

    private static JSONArray recipients(Collection<String> addresses) {
        JSONArray array = new JSONArray();
        for (String address : addresses) {
            JSONObject email = new JSONObject();
            email.put("address", address);
            JSONObject recipient = new JSONObject();
            recipient.put("emailAddress", email);
            array.put(recipient);
        }
        return array;
    }

    public static List<String> splitAddresses(String value) {
        List<String> result = new ArrayList<String>();
        if (value != null) {
            for (String address : value.split("[,;]")) {
                if (!address.trim().isEmpty()) {
                    result.add(address.trim());
                }
            }
        }
        return result;
    }

    private static void sleep(long millis) throws IOException {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Microsoft Graph send interrupted", e);
        }
    }

    private static String read(InputStream in) throws IOException {
        if (in == null) {
            return "";
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } finally {
            in.close();
        }
    }

    private static String encode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }

    protected static class HttpResponse {
        final int status;
        final String body;
        final String retryAfter;

        HttpResponse(int status, String body, String retryAfter) {
            this.status = status;
            this.body = body;
            this.retryAfter = retryAfter;
        }
    }

    private static class CachedToken {
        final String accessToken;
        final long expiresAt;

        CachedToken(String accessToken, long expiresAt) {
            this.accessToken = accessToken;
            this.expiresAt = expiresAt;
        }
    }
}
