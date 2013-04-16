package org.jenkinsci.plugins.stashNotifier.util;

import junit.framework.TestCase;

import org.apache.http.Header;
import org.apache.http.client.methods.HttpPost;

import com.trilead.ssh2.crypto.Base64;

/**
 * Test case for the {@link BasicStashRequestConfigurator} class.
 * 
 * @author Michael Irwin
 */
public class BasicStashRequestConfiguratorTest extends TestCase {

	private String username;
	private String password;
	private BasicStashRequestConfigurator configurator;
	
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		username = "some.user.name";
		password = "aBadPassw0rd";
		configurator = new BasicStashRequestConfigurator(username, password);
	}
	
	/**
	 * Validate that the Authorization header is set to use BASIC auth, using
	 * the provided username and password.
	 */
	public void testConfiguration() throws Exception {
		HttpPost post = new HttpPost();
		configurator.configureStashRequest(post);
		assertTrue(post.containsHeader("Authorization"));
		
		Header authHeader = post.getHeaders("Authorization")[0];
		assertFalse(authHeader.getValue().isEmpty());
		
		String authValue = authHeader.getValue().replace("Basic", "").trim();
		String authString = new String(Base64.decode(authValue.toCharArray()));
		assertEquals(username + ":" + password, authString);
	}
}
