package org.jenkinsci.plugins.stashNotifier.util;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import hudson.model.AbstractBuild;
import jenkins.model.Jenkins;
import junit.framework.TestCase;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.jenkinsci.plugins.stashNotifier.NotificationResult;
import org.mockito.Mockito;

/**
 * Test case for the {@link ConfigurableStashNotifierService} class.
 * 
 * @author Michael Irwin
 */
public class ConfigurableStashNotifierServiceTest extends TestCase {

	private String baseUrl;
	private String commitSha1;
	private BuildEntityFactory entityFactory;
	private StashRequestConfigurator requestConfigurator;
	private ConfigurableStashNotifierService notifier;
	
	
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		
		baseUrl = "http://jenkins.localhost/";
		commitSha1 = "2c5bc0bb5914043bf4390521c4f2abaf1246e1a5";
		entityFactory = Mockito.mock(BuildEntityFactory.class);
		requestConfigurator = Mockito.mock(StashRequestConfigurator.class);
		
		notifier = new ConfigurableStashNotifierService(baseUrl, entityFactory, 
				requestConfigurator);
	}
	
	public void testUrl() {
		assertEquals(baseUrl + "/rest/build-status/1.0/commits/" + commitSha1,
				notifier.getUrl(commitSha1));
	}
	
	public void testSuccess() throws Exception {
		NotificationResult message = runTest(204, null);
		assertTrue(message.indicatesSuccess);
		assertNull(message.message);
	}

	public void testFailure() throws Exception {
		String errorMessage = "Page not found";
		HttpEntity entity = new StringEntity(errorMessage);
		NotificationResult message = runTest(404, entity);
		assertFalse(message.indicatesSuccess);
		assertEquals(errorMessage, message.message);
	}

	@SuppressWarnings("rawtypes")
	private NotificationResult runTest(int statusCode, HttpEntity entity) 
			throws Exception {
		AbstractBuild build = mock(AbstractBuild.class);
		String commitSha = "2c5bc0bb5914043bf4390521c4f2abaf1246e1a5";
		HttpClient httpClient = mock(HttpClient.class);
		HttpResponse response = mock(HttpResponse.class);
		StatusLine statusLine = mock(StatusLine.class);

		when(httpClient.execute(any(HttpPost.class))).thenReturn(response);
		when(response.getStatusLine()).thenReturn(statusLine);
		when(statusLine.getStatusCode()).thenReturn(statusCode);
		if (entity != null)
			when(response.getEntity()).thenReturn(entity);
		
 		NotificationResult result = 
 				notifier.notifyStash(build, commitSha, httpClient);

 		verify(httpClient, times(1)).execute(any(HttpPost.class));
 		verify(response, times(1)).getStatusLine();
 		verify(statusLine, times(1)).getStatusCode();
 		verify(requestConfigurator).configureStashRequest(any(HttpPost.class));
		verify(entityFactory, times(1)).getContentType();
		verify(entityFactory).createBuildEntity(any(Jenkins.class), Mockito.eq(build));
		if (entity != null)
			verify(response, times(1)).getEntity();
		return result;
	}
	
}
