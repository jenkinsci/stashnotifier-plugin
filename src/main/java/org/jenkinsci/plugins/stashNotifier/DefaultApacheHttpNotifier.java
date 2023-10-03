package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.common.CertificateCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ProxyConfiguration;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.config.CookieSpecs;
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
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
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

class DefaultApacheHttpNotifier implements HttpNotifier {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultApacheHttpNotifier.class);

    @Override
    public @NonNull NotificationResult send(@NonNull URI uri, @NonNull JSONObject payload, @NonNull NotificationSettings settings, @NonNull NotificationContext context) {
        PrintStream logger = context.getLogger();
        try (CloseableHttpClient client = getHttpClient(logger, uri, settings.isIgnoreUnverifiedSSL())) {
            HttpPost req = createRequest(uri, payload, settings.getCredentials(), context);
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
            final Credentials credentials,
            @NonNull NotificationContext context) throws AuthenticationException {
        HttpPost req = new HttpPost(uri.toString());

        if (credentials != null) {
            if (credentials instanceof UsernamePasswordCredentials) {
                LOGGER.debug("createRequest - UsernamePasswordCredentials");
                req.addHeader(new BasicScheme().authenticate(
                        new org.apache.http.auth.UsernamePasswordCredentials(
                                ((UsernamePasswordCredentials)credentials).getUsername(),
                                ((UsernamePasswordCredentials)credentials).getPassword().getPlainText()),
                        req,
                        null));
            }
            else if (credentials instanceof StringCredentials) {
                LOGGER.debug("createRequest - StringCredentials/secret text");
                req.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + ((StringCredentials)credentials).getSecret().getPlainText());
            } 
            else {
                throw new AuthenticationException("Unsupported credials");
            }
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
                .setConnectionRequestTimeout(timeoutInMilliseconds)
                .setCookieSpec(CookieSpecs.STANDARD);

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
                logger.println("Could not establish SSL context");
                LOGGER.error("Could not establish SSL context", nsae);
            } catch (KeyManagementException | KeyStoreException e) {
                logger.println("Could not initialize SSL context");
                LOGGER.error("Could not initialize SSL context", e);
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
        Jenkins jenkins = Jenkins.get();
        ProxyConfiguration proxyConfig = jenkins.proxy;
        if (proxyConfig == null) {
            return;
        }

        Proxy proxy = proxyConfig.createProxy(url.getHost());
        if (proxy == null || proxy.type() != Proxy.Type.HTTP) {
            return;
        }

        SocketAddress addr = proxy.address();
        if (!(addr instanceof InetSocketAddress)) {
            return;
        }

        InetSocketAddress proxyAddr = (InetSocketAddress) addr;
        HttpHost proxyHost = new HttpHost(proxyAddr.getAddress().getHostAddress(), proxyAddr.getPort());
        builder.setProxy(proxyHost);

        String proxyUser = proxyConfig.getUserName();
        if (proxyUser != null) {
            String proxyPass = Secret.toString(proxyConfig.getSecretPassword());
            BasicCredentialsProvider cred = new BasicCredentialsProvider();
            cred.setCredentials(new AuthScope(proxyHost),
                    new org.apache.http.auth.UsernamePasswordCredentials(proxyUser, proxyPass));
            builder.setDefaultCredentialsProvider(cred)
                    .setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
        }
    }
}
