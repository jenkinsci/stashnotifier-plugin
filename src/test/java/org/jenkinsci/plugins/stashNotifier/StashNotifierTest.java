package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.EnvVars;
import hudson.ProxyConfiguration;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Item;
import hudson.plugins.git.Revision;
import hudson.plugins.git.util.Build;
import hudson.plugins.git.util.BuildData;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.apache.http.HttpHost;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthenticationStrategy;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Secret.class, Jenkins.class, HttpClientBuilder.class})
@PowerMockIgnore("javax.net.ssl.*")
public class StashNotifierTest
{
	final static String sha1 = "1234567890123456789012345678901234567890";
	private HttpClientBuilder httpClientBuilder;
	private Jenkins jenkins;

	public StashNotifier buildStashNotifier(String stashBaseUrl) {
		return new StashNotifier(
				stashBaseUrl,
				"scot",
				true,
				null,
				true,
				null,
				false,
				false,
				false,
				false);
	}

	StashNotifier sn;
	BuildListener buildListener;
	AbstractBuild<?,?> build;

	@Before
	public void setUp() throws IOException, InterruptedException {
		PowerMockito.mockStatic(Secret.class);
		PowerMockito.mockStatic(Jenkins.class);
		PowerMockito.mockStatic(HttpClientBuilder.class);

		buildListener = mock(BuildListener.class);
		jenkins = mock(Jenkins.class);
		build = mock(AbstractBuild.class);
		AbstractProject project = mock(AbstractProject.class);
		EnvVars environment = mock(EnvVars.class);
		PrintStream logger = System.out;
		Secret secret = mock(Secret.class);
		httpClientBuilder = PowerMockito.mock(HttpClientBuilder.class);
		CloseableHttpClient client = mock(CloseableHttpClient.class);
		ClientConnectionManager connectionManager = mock(ClientConnectionManager.class);
		CloseableHttpResponse resp = mock(CloseableHttpResponse.class);
		HttpUriRequest req = mock(HttpUriRequest.class);
		StatusLine statusLine = mock(StatusLine.class);
		BuildData action = mock(BuildData.class);
		Revision revision = mock(Revision.class);
		Build lastBuild = mock(Build.class);
		List<BuildData> actions = Collections.singletonList(action);

		when(Jenkins.getInstance()).thenReturn(jenkins);
		when(jenkins.getRootUrl()).thenReturn("http://localhost/");
		when(build.getEnvironment(buildListener)).thenReturn(environment);
		when(action.getLastBuiltRevision()).thenReturn(revision);
		when(revision.getSha1String()).thenReturn(sha1);
		when(build.getProject()).thenReturn(project);
                when(build.getFullDisplayName()).thenReturn("foo");
		when(build.getUrl()).thenReturn("foo");
		when(build.getActions(BuildData.class)).thenReturn(actions);
		when(environment.expand(anyString())).thenReturn(sha1);
		when(buildListener.getLogger()).thenReturn(logger);
		when(Secret.fromString("tiger")).thenReturn(secret);
		when(Secret.toString(secret)).thenReturn("tiger");
		when(secret.getPlainText()).thenReturn("tiger");
		when(HttpClientBuilder.create()).thenReturn(httpClientBuilder);
		when(httpClientBuilder.build()).thenReturn(client);
		when(client.getConnectionManager()).thenReturn(connectionManager);
		when(client.execute((HttpUriRequest)anyObject())).thenReturn(resp);
		when(resp.getStatusLine()).thenReturn(statusLine);
		when(statusLine.getStatusCode()).thenReturn(204);
		action.lastBuild = lastBuild;
		when(lastBuild.getMarked()).thenReturn(revision);

		sn = buildStashNotifier("http://localhost");
	}

	@Test
	public void test_prebuild_normal() {
		assertTrue(sn.prebuild(build, buildListener));
	}

	@Test
	public void test_prebuild_null_revision() {
		when(build.getActions(BuildData.class)).thenReturn(Collections.singletonList(mock(BuildData.class)));
		assertTrue(sn.prebuild(build, buildListener));
	}

    @Test
    public void test_build_http_client_with_proxy() throws Exception {
        //given
        StashNotifier sn = spy(this.sn);
        doReturn(new ArrayList<Credentials>()).when(sn).lookupCredentials(
                Mockito.<Class>anyObject(),
                Mockito.<Item>anyObject(),
                Mockito.<Authentication>anyObject(),
                Mockito.<ArrayList<DomainRequirement>>anyObject());

        String address = "192.168.1.1";
        int port = 8080;
        String login = "admin";
        String password = "123";

        Secret secret = mock(Secret.class);
        when(Secret.fromString(password)).thenReturn(secret);
        when(Secret.toString(secret)).thenReturn(password);
        when(secret.getPlainText()).thenReturn(password);

        when(httpClientBuilder.setProxy(any(HttpHost.class))).thenReturn(httpClientBuilder);
        when(httpClientBuilder.setDefaultCredentialsProvider(any(CredentialsProvider.class))).thenReturn(httpClientBuilder);
        when(httpClientBuilder.setProxyAuthenticationStrategy(any(AuthenticationStrategy.class))).thenReturn(httpClientBuilder);

        jenkins.proxy = new ProxyConfiguration(address, port, login, password);
        PrintStream logger = mock(PrintStream.class);

        //when
        sn.getHttpClient(logger, build);

        //then
        ArgumentCaptor<HttpHost> proxyCaptor = ArgumentCaptor.forClass(HttpHost.class);
        verify(httpClientBuilder).setProxy(proxyCaptor.capture());
        HttpHost proxy = proxyCaptor.getValue();
        //address
        assertThat(proxy.getHostName(), is(address));
        assertThat(proxy.getPort(), is(port));
        assertThat(proxy.getSchemeName(), is("http"));

        ArgumentCaptor<CredentialsProvider> credentialsProviderCaptor = ArgumentCaptor.forClass(CredentialsProvider.class);
        verify(httpClientBuilder).setDefaultCredentialsProvider(credentialsProviderCaptor.capture());
        CredentialsProvider credentialsProvider = credentialsProviderCaptor.getValue();
        org.apache.http.auth.UsernamePasswordCredentials credentials = (UsernamePasswordCredentials) credentialsProvider.getCredentials(new AuthScope(proxy));
        //credentials
        assertThat(credentials.getUserName(), is(login));
        assertThat(credentials.getPassword(), is(password));
    }

    @Test
    public void test_build_http_client_https() throws Exception {
        //given
        sn = PowerMockito.spy(buildStashNotifier("https://localhost"));
        doReturn(new ArrayList<Credentials>()).when(sn).lookupCredentials(
                Mockito.<Class>anyObject(),
                Mockito.<Item>anyObject(),
                Mockito.<Authentication>anyObject(),
                Mockito.<ArrayList<DomainRequirement>>anyObject());
        PrintStream logger = mock(PrintStream.class);

        //when
        sn.getHttpClient(logger, build);

        //then
        verify(httpClientBuilder).setSSLSocketFactory(any(SSLConnectionSocketFactory.class));
        verify(httpClientBuilder).setConnectionManager(any(HttpClientConnectionManager.class));
    }
}
