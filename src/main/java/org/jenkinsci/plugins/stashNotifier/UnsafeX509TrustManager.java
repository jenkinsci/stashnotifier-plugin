package org.jenkinsci.plugins.stashNotifier;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * A credential checker used to avoid exceptions with self signed SSL 
 * certificates.
 */
public class UnsafeX509TrustManager implements X509TrustManager {

	public final void checkClientTrusted(X509Certificate[] arg0, String arg1)
			throws CertificateException {
		// don't throw any exception
	}

	public void checkServerTrusted(X509Certificate[] arg0, String arg1)
			throws CertificateException {
		// don't throw any exception
	}

	public X509Certificate[] getAcceptedIssuers() {
		return null;
	}
}
