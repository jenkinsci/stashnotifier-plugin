package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.common.CertificateCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import hudson.ProxyConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

public class DefaultApacheHttpNotifier implements HttpNotifier {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultApacheHttpNotifier.class);

    @Override
    public NotificationResult send(URI uri, JSONObject payload, NotificationSettings settings, NotificationContext context) {
        PrintStream logger = context.getLogger();
        try (CloseableHttpClient client = getHttpClient(logger, uri, settings.isIgnoreUnverifiedSSL())) {
            HttpPost req = createRequest(uri, payload, settings.getCredentials());
            HttpResponse res = client.execute(req);
            if (res.getStatusLine().getStatusCode() != 204) {
                return NotificationResult.newFailure(EntityUtils.toString(res.getEntity()));
            } else {
                return NotificationResult.newSuccess();
            }
        } catch (Exception e) {
            LOGGER.warn("{} failed to send {} to Bitbucket Server at {}", context.getRunId(), payload, uri, e);
            logger.println("Failed to notify Bitbucket Server");
            return NotificationResult.newFailure(e.getMessage());
        }
    }

    HttpPost createRequest(
            final URI uri,
            final JSONObject payload,
            final UsernamePasswordCredentials credentials) throws AuthenticationException {

        HttpPost req = new HttpPost(uri.toString());

        if (credentials != null) {
            req.addHeader(new BasicScheme().authenticate(
                    new org.apache.http.auth.UsernamePasswordCredentials(
                            credentials.getUsername(),
                            credentials.getPassword().getPlainText()),
                    req,
                    null));
        }

        req.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        req.setEntity(new StringEntity(payload.toString(), "UTF-8"));

        return req;
    }

    CloseableHttpClient getHttpClient(PrintStream logger, URI stashServer, boolean ignoreUnverifiedSSL) throws Exception {
        final int timeoutInMilliseconds = 60_000;

        RequestConfig.Builder requestBuilder = RequestConfig.custom()
                .setSocketTimeout(timeoutInMilliseconds)
                .setConnectTimeout(timeoutInMilliseconds)
                .setConnectionRequestTimeout(timeoutInMilliseconds);

        HttpClientBuilder clientBuilder = HttpClients.custom();
        clientBuilder.setDefaultRequestConfig(requestBuilder.build());

        URL url = stashServer.toURL();

        if (url.getProtocol().equals("https") && ignoreUnverifiedSSL) {
            // add unsafe trust manager to avoid thrown SSLPeerUnverifiedException
            try {
                SSLContext sslContext = buildSslContext(ignoreUnverifiedSSL, null);
                SSLConnectionSocketFactory sslConnSocketFactory = new SSLConnectionSocketFactory(
                        sslContext,
                        new String[]{"TLSv1", "TLSv1.1", "TLSv1.2"},
                        null,
                        NoopHostnameVerifier.INSTANCE
                );
                clientBuilder.setSSLSocketFactory(sslConnSocketFactory);

                Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("https", sslConnSocketFactory)
                        .register("http", PlainConnectionSocketFactory.INSTANCE)
                        .build();

                HttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(registry);
                clientBuilder.setConnectionManager(connectionManager);
            } catch (NoSuchAlgorithmException nsae) {
                logger.println("Couldn't establish SSL context:");
                nsae.printStackTrace(logger);
            } catch (KeyManagementException | KeyStoreException e) {
                logger.println("Couldn't initialize SSL context:");
                e.printStackTrace(logger);
            }
        }

        // Configure the proxy, if needed
        // Using the Jenkins methods handles the noProxyHost settings
        configureProxy(clientBuilder, url);

        return clientBuilder.build();
    }

    SSLContext buildSslContext(boolean ignoreUnverifiedSSL, Credentials credentials) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLContextBuilder contextBuilder = SSLContexts.custom();
        contextBuilder.setProtocol("TLS");
        if (credentials instanceof CertificateCredentials) {
            contextBuilder.loadKeyMaterial(
                    ((CertificateCredentials) credentials).getKeyStore(),
                    ((CertificateCredentials) credentials).getPassword().getPlainText().toCharArray());
        }
        if (ignoreUnverifiedSSL) {
            contextBuilder.loadTrustMaterial(null, TrustAllStrategy.INSTANCE);
        }
        return contextBuilder.build();
    }

    void configureProxy(HttpClientBuilder builder, URL url) {
        Jenkins jenkins = Jenkins.getInstance();
        ProxyConfiguration proxyConfig = jenkins.proxy;
        if (proxyConfig == null) {
            return;
        }

        Proxy proxy = proxyConfig.createProxy(url.getHost());
        if (proxy == null || proxy.type() != Proxy.Type.HTTP) {
            return;
        }

        SocketAddress addr = proxy.address();
        if (addr == null || !(addr instanceof InetSocketAddress)) {
            return;
        }

        InetSocketAddress proxyAddr = (InetSocketAddress) addr;
        HttpHost proxyHost = new HttpHost(proxyAddr.getAddress().getHostAddress(), proxyAddr.getPort());
        builder.setProxy(proxyHost);

        String proxyUser = proxyConfig.getUserName();
        if (proxyUser != null) {
            String proxyPass = proxyConfig.getPassword();
            BasicCredentialsProvider cred = new BasicCredentialsProvider();
            cred.setCredentials(new AuthScope(proxyHost),
                    new org.apache.http.auth.UsernamePasswordCredentials(proxyUser, proxyPass));
            builder.setDefaultCredentialsProvider(cred)
                    .setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
        }
    }
}
