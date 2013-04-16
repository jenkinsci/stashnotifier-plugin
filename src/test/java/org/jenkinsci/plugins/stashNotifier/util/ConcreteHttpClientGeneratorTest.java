package org.jenkinsci.plugins.stashNotifier.util;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;

import junit.framework.TestCase;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.impl.client.DefaultHttpClient;

/**
 * Test case for the {@link ConcreteHttpClientFactory} test class.
 * 
 * @author Michael Irwin
 */
public class ConcreteHttpClientGeneratorTest extends TestCase {

	private PrintStream logger;
	private InstrumentedConcreteHttpClientFactory generator;
	
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		logger = new PrintStream(new ByteArrayOutputStream());
		generator = new InstrumentedConcreteHttpClientFactory();
	}
	
	public void testNonSslGeneration() {
		generator.getHttpClient(false, false, logger);
		assertFalse(generator.wasClientCustomConfigured());
		assertFalse(generator.wasSslContextCreated());
		assertFalse(generator.wasSchemeRegistryCreated());
		
		generator.getHttpClient(false, true, logger);
		assertFalse(generator.wasClientCustomConfigured());
		assertFalse(generator.wasSslContextCreated());
		assertFalse(generator.wasSchemeRegistryCreated());
	}
	
	public void testSslUsingDefaultCertificates() {
		generator.getHttpClient(true, false, logger);
		assertFalse(generator.wasClientCustomConfigured());
		assertFalse(generator.wasSslContextCreated());
		assertFalse(generator.wasSchemeRegistryCreated());
	}
	
	public void testSslAllowingAllowCertificates() {
		generator.getHttpClient(true, true, logger);
		assertTrue(generator.wasClientCustomConfigured());
		assertTrue(generator.wasSslContextCreated());
		assertTrue(generator.wasSchemeRegistryCreated());
	}
	
	/**
	 * An instrumented extension of the ConcreteHttpClientFactory that delegates
	 * all functionality to the parent, but checks that various methods are
	 * actually being called as expected.
	 * 
	 * @author Michael Irwin
	 */
	private class InstrumentedConcreteHttpClientFactory 
			extends ConcreteHttpClientFactory {
		private boolean clientConfigured = false;
		private boolean sslContextCreated = false;
		private boolean schemeRegistryCreated = false;
		
		public boolean wasClientCustomConfigured() {
			return clientConfigured;
		}
		
		public boolean wasSchemeRegistryCreated() {
			return schemeRegistryCreated;
		}
		
		public boolean wasSslContextCreated() {
			return sslContextCreated;
		}
		
		@Override
		protected HttpClient createHttpClient(Boolean useConfigured,
				PrintStream logger) {
			clientConfigured = useConfigured;
			return super.createHttpClient(useConfigured, logger);
		}
		
		@Override
		protected SSLContext createContext() throws NoSuchAlgorithmException,
				KeyManagementException {
			sslContextCreated = true;
			return super.createContext();
		}
		
		@Override
		protected SchemeRegistry createScheme(SSLContext sslContext) {
			schemeRegistryCreated = true;
			return super.createScheme(sslContext);
		}
	}
}
