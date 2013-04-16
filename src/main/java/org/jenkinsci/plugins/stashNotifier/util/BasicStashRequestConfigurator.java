package org.jenkinsci.plugins.stashNotifier.util;

import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.auth.BasicScheme;

/**
 * An implementation of the {@link StashRequestConfigurator} that adds an
 * Authentication header, using BASIC authentication.
 * 
 * @author Michael Irwin
 */
public class BasicStashRequestConfigurator implements StashRequestConfigurator {

	private final String username;
	private final String password;
	
	public BasicStashRequestConfigurator(String stashUsername, 
			String stashPassword) {
		this.username = stashUsername;
		this.password = stashPassword;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void configureStashRequest(HttpPost post) {
		post.addHeader(BasicScheme.authenticate(
				new UsernamePasswordCredentials(username,password), 
				"UTF-8", 
				false));
	}
}
