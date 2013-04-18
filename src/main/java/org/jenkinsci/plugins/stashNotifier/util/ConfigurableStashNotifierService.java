package org.jenkinsci.plugins.stashNotifier.util;

import jenkins.model.Jenkins;
import hudson.model.AbstractBuild;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.jenkinsci.plugins.stashNotifier.NotificationResult;

/**
 * An implementation of the {@link StashNotifierService} that has its
 * dependencies injected during construction.  This can allow future adjustments
 * if OAuth becomes available, or if the API changes to use XML, etc.
 * 
 * @author Michael Irwin
 */
public class ConfigurableStashNotifierService implements StashNotifierService {

	private final String stashServerBaseUrl;
	private final BuildEntityFactory entityFactory;
	private final StashRequestConfigurator requestConfigurator;
	
	public ConfigurableStashNotifierService(String stashServerBaseUrl,
			BuildEntityFactory entityFactory,
			StashRequestConfigurator requestConfigurator) {
		this.stashServerBaseUrl = stashServerBaseUrl;
		this.entityFactory = entityFactory;
		this.requestConfigurator = requestConfigurator;
	}
	
	@SuppressWarnings("rawtypes")
	public NotificationResult notifyStash(AbstractBuild build, 
			String commitSha1, 
			HttpClient httpClient) throws Exception {

		HttpPost req = new HttpPost(getUrl(commitSha1));
		requestConfigurator.configureStashRequest(req);
		req.addHeader("Content-type", entityFactory.getContentType());		
		req.setEntity(entityFactory
				.createBuildEntity(Jenkins.getInstance(), build));
		
		HttpResponse res = httpClient.execute(req);
		if (res.getStatusLine().getStatusCode() != 204) {
			return NotificationResult.newFailure(
					EntityUtils.toString(res.getEntity()));
		} else {
			return NotificationResult.newSuccess();
		}
	}
	
	protected String getUrl(String commitSha1) {
		return stashServerBaseUrl + "/rest/build-status/1.0/commits/" + 
				commitSha1;
	}
}
