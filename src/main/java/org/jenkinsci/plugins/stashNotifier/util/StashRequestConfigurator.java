package org.jenkinsci.plugins.stashNotifier.util;

import org.apache.http.client.methods.HttpPost;

/**
 * A factory interface that is used to created the HttpPost used to communicate
 * with the Stash Build API.
 * 
 * @author Michael Irwin
 */
public interface StashRequestConfigurator {
	
	/**
	 * Method to configure/decorate a HttpPost object to allow it talk to the
	 * Stash Build API.
	 * @param post the HttpPost to configure
	 */
	void configureStashRequest(HttpPost post);
	
}
