package org.jenkinsci.plugins.stashNotifier;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import hudson.Launcher;
import hudson.model.BuildListener;
import hudson.model.AbstractBuild;
import hudson.plugins.git.Revision;
import hudson.plugins.git.util.BuildData;
import hudson.tasks.BuildStepMonitor;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import javax.net.ssl.SSLPeerUnverifiedException;

import jenkins.model.Jenkins;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ClientConnectionManager;
import org.jenkinsci.plugins.stashNotifier.util.HttpClientFactory;
import org.jenkinsci.plugins.stashNotifier.util.StashNotifierService;
import org.jvnet.hudson.test.HudsonTestCase;

/**
 * Test case for the {@link StashNotifier} class.
 * 
 * @author Michael Irwin
 */
@SuppressWarnings("rawtypes")
public class StashNotifierTest extends HudsonTestCase {

	private StashNotifier notifier;
	private String rootUrl, baseUrl, username, password, commitSha1;
	
	private HttpClientFactory httpClientFactory;
	private StashNotifierService stashNotifierService;
	private Jenkins jenkins;
	private AbstractBuild build;
	private BuildData buildData;
	private Revision lastRevision;
	private Launcher launcher;
	private MockedLogger logger;
	private BuildListener listener;
	
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		rootUrl = "http://jenkins.localhost";
		baseUrl = "/jenkins/";
		username = "stash_admin";
		password = "stashPassw0rd";
		commitSha1 = "2c5bc0bb5914043bf4390521c4f2abaf1246e1a5";
		
		httpClientFactory = mock(HttpClientFactory.class);
		stashNotifierService = mock(StashNotifierService.class);
		jenkins = mock(Jenkins.class);
		build = mock(AbstractBuild.class);
		buildData = mock(BuildData.class);
		lastRevision = mock(Revision.class);
		launcher = mock(Launcher.class);
		logger = new MockedLogger();
		listener = mock(BuildListener.class);
		when(listener.getLogger()).thenReturn(logger);

		notifier = new StashNotifier(baseUrl, username, password, true);
	}
	
	public void testCreation() throws Exception {
		boolean allowsCerts = true;
		notifier = new StashNotifier(baseUrl, username, password, allowsCerts);
		assertEquals(baseUrl, notifier.getStashServerBaseUrl());
		assertEquals(username, notifier.getStashUserName());
		assertEquals(password, notifier.getStashUserPassword());
		assertEquals(allowsCerts, notifier.getIgnoreUnverifiedSSLPeer());
		assertEquals(BuildStepMonitor.BUILD, 
				notifier.getRequiredMonitorService());
	}
	
	public void testMissingJenkinsRootUrl() {
		notifier.setJenkins(jenkins);
		when(jenkins.getRootUrl()).thenReturn(null);
		
		boolean result = notifier.perform(build, launcher, listener);
		assertTrue(result);
		assertEquals("Cannot notify Stash! (Jenkins Root URL not configured)",
				logger.getLastLine());
	}
	
	public void testMissingCommitData() {
		notifier.setJenkins(jenkins);
		when(jenkins.getRootUrl()).thenReturn(rootUrl);
		when(build.getAction(BuildData.class)).thenReturn(null);
		
		boolean result = notifier.perform(build, launcher, listener);
		assertTrue(result);
		assertEquals("found no commit info", logger.getLastLine());
	}
	
	private void runFullPerform(NotificationResult notificationResult, 
			Class<? extends Exception> toThrow) throws Exception {
		HttpClient client = mock(HttpClient.class);
		ClientConnectionManager connectionManager = mock(ClientConnectionManager.class);
		when(client.getConnectionManager()).thenReturn(connectionManager);
		
		notifier.setNotifierService(stashNotifierService);
		notifier.setJenkins(jenkins);
		notifier.setHttpClientfactory(httpClientFactory);
		when(jenkins.getRootUrl()).thenReturn(rootUrl);
		when(build.getAction(BuildData.class)).thenReturn(buildData);
		when(buildData.getLastBuiltRevision()).thenReturn(lastRevision);
		when(lastRevision.getSha1String()).thenReturn(commitSha1);
		when(httpClientFactory.getHttpClient(false, true, logger))
			.thenReturn(client);
		
		if (notificationResult != null) {
			when(stashNotifierService.notifyStash(build, commitSha1, client))
				.thenReturn(notificationResult);
		} else {
			when(stashNotifierService.notifyStash(build, commitSha1, client))
				.thenThrow(toThrow);
		}
		
		boolean performResult = notifier.perform(build, launcher, listener);
		assertTrue(performResult);
	}
	
	public void testSuccessfulNotification() throws Exception {
		NotificationResult result = NotificationResult.newSuccess();
		runFullPerform(result, null);
		assertEquals("Notified Stash for commit with id " + commitSha1, 
				logger.getLastLine());
	}
	
	public void testFailedNotification() throws Exception {
		String failMessage = "FAILURE";
		NotificationResult result = NotificationResult.newFailure(failMessage);
		runFullPerform(result, null);
		assertEquals("Failed to notify Stash for commit "
				+ commitSha1 
				+ " (" + failMessage + ")", 
				logger.getLastLine());
	}
	
	public void testThrowsSslException() throws Exception {
		runFullPerform(null, SSLPeerUnverifiedException.class);
		assertTrue(logger.getLastLine()
				.startsWith("SSLPeerUnverifiedException caught"));
	}
	
	public void testThrowsOtherException() throws Exception {
		runFullPerform(null, NullPointerException.class);
		assertTrue(logger.getLastLine()
				.startsWith("Caught exception while notifying Stash"));
	}
	
	/**
	 * A mocked logger that stores the last line that was println'ed.
	 * 
	 * @author Michael Irwin
	 */
	private class MockedLogger extends PrintStream {
		private String lastLine;
		
		public MockedLogger() {
			super(new ByteArrayOutputStream());
		}
		
		@Override
		public void println(String line) {
			this.lastLine = line;
			super.println();
		}
		
		public String getLastLine() {
			return lastLine;
		}
	}
}
