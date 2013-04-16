package org.jenkinsci.plugins.stashNotifier.util;

import hudson.model.AbstractBuild;

import org.apache.http.client.HttpClient;
import org.jenkinsci.plugins.stashNotifier.NotificationResult;

/**
 * A service interface that is used to actually communicate with the Stash
 * Build API.
 * 
 * @author Michael Irwin
 */
public interface StashNotifierService {

	/**
	 * Notify Stash of the results of the following build.
	 * @param build The build to notify Stash of
	 * @param commitSha1 The SHA1 of the commit prompting the build
	 * @param httpClient The HttpClient to use for sending the notification
	 * @return The result of the notification.
	 * @throws Exception Any exception that can be thrown.
	 */
	@SuppressWarnings("rawtypes")
	NotificationResult notifyStash(AbstractBuild build,	String commitSha1, 
			HttpClient httpClient) throws Exception; 
}
