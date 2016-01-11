package me.batanov.jenkins.plugins.atlassian.bitbucket;

import me.batanov.jenkins.plugins.atlassian.bitbucket.notifier.exception.NotificationFailedException;
import net.sf.json.JSONObject;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.protocol.BasicHttpContext;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 20:50
 */
public class StashApiServer implements ApiServer {

    public static final String CHARSET = "UTF-8";
    public static final String CONTENT_TYPE = "application/json";
    private String apiUrl;
    private HttpClient httpClient;
    private UsernamePasswordCredentials credentials;

    private URL url;

    public StashApiServer(String stringApiUrl, HttpClient httpClient, UsernamePasswordCredentials credentials) throws MalformedURLException {
        this.apiUrl = stringApiUrl;
        this.httpClient = httpClient;
        this.credentials = credentials;
        this.url = new URL(stringApiUrl);
    }

    @Nonnull
    public Map<String, Object> performApiCall(String method, @Nonnull Map<String, Object> map) throws AuthenticationException {
        JSONObject json = JSONObject.fromObject(map);

        HttpPost req = new HttpPost(apiUrl + method);

        req.addHeader(new BasicScheme().authenticate(credentials, req, new BasicHttpContext()));
        req.addHeader("Content-type", CONTENT_TYPE);
        req.setEntity(new StringEntity(json.toString(), CHARSET));

        try {
            HttpResponse res = httpClient.execute(req);
            return JSONObject.fromObject(res.getEntity().toString());
        } catch (IOException exception) {
            throw new NotificationFailedException();
        }
    }
}
