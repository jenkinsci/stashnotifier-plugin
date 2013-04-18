package org.jenkinsci.plugins.stashNotifier.util;

import java.io.PrintStream;

import org.apache.http.client.HttpClient;

/**
 * Defines a generator that will create a HttpClient to communicate with Stash.
 * 
 * @author Michael Irwin
 */
public interface HttpClientFactory {

	/**
	 * Generate a HttpClient to communicate with the Stash instance.
	 * @param usingSsl True if using ssl.
	 * @param trustAllCerts True if all certs should be trusted.
	 * @param logger The logger to send messages.
	 * @return An HttpClient configured to communicate with the Stash instance.
	 */
	HttpClient getHttpClient(Boolean usingSsl, Boolean trustAllCerts, 
			PrintStream logger);
}
