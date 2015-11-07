package org.jenkinsci.plugins.stashNotifier;

import hudson.EnvVars;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.plugins.git.Revision;
import hudson.plugins.git.util.Build;
import hudson.plugins.git.util.BuildData;
import hudson.util.Secret;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Collections;
import java.util.List;
import jenkins.model.Jenkins;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.mockito.Mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Secret.class, Jenkins.class, HttpClientBuilder.class})
public class StashNotifierTest
{
	final static String sha1 = "1234567890123456789012345678901234567890";
	public StashNotifier buildStashNotifier() {
		return new StashNotifier(
			"http://localhost",
			"scot",
			true,
			null,
			true,
			null,
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
		Jenkins jenkins = mock(Jenkins.class);
		build = mock(AbstractBuild.class);
		AbstractProject project = mock(AbstractProject.class);
		EnvVars environment = mock(EnvVars.class);
		PrintStream logger = System.out;
		Secret secret = mock(Secret.class);
		HttpClientBuilder builder = mock(HttpClientBuilder.class);
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
		when(HttpClientBuilder.create()).thenReturn(builder);
		when(builder.build()).thenReturn(client);
		when(client.getConnectionManager()).thenReturn(connectionManager);
		when(client.execute((HttpUriRequest)anyObject())).thenReturn(resp);
		when(resp.getStatusLine()).thenReturn(statusLine);
		when(statusLine.getStatusCode()).thenReturn(204);
		action.lastBuild = lastBuild;
		when(lastBuild.getMarked()).thenReturn(revision);

		sn = buildStashNotifier();
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
}
