/*
 * Copyright 2013 Georg Gruetter
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 package org.jenkinsci.plugins.stashNotifier;
 
import hudson.EnvVars;
import hudson.Launcher;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.AbstractProject;
import hudson.model.Result;
import hudson.plugins.git.util.BuildData;
import hudson.tasks.Publisher;
import hudson.tasks.Notifier;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.util.Secret;
import net.sf.json.JSONObject;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.util.EntityUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;
import javax.servlet.ServletException;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import jenkins.model.Jenkins;

/**
 * Notifies a configured Atlassian Stash server instance of build results
 * through the Stash build API.
 * <p>
 * Only basic authentication is supported at the moment.
 * 
 * @author	Georg Gruetter
 */
public class StashNotifier extends Notifier {
	
	// attributes --------------------------------------------------------------

	/** base url of Stash server, e. g. <tt>http://localhost:7990</tt>. */
	private final String stashServerBaseUrl;
	
	/** name of Stash user for authentication with Stash build API. */
	private final String stashUserName;
	
	/** password of Stash user for authentication with Stash build API. */
	private final String stashUserPassword;
	
	/** if true, ignore exception thrown in case of an unverified SSL peer. */
	private final boolean ignoreUnverifiedSSLPeer;

	/** specify the commit from config */
	private final String commitSha1;
	
	// public members ----------------------------------------------------------

	public BuildStepMonitor getRequiredMonitorService() {
		return BuildStepMonitor.BUILD;
	}

	@DataBoundConstructor
	public StashNotifier(
			String stashServerBaseUrl,
			String stashUserName,
			String stashUserPassword,
			boolean ignoreUnverifiedSSLPeer,
			String commitSha1) {
		this.stashServerBaseUrl = stashServerBaseUrl;
		this.stashUserName = stashUserName;
		this.stashUserPassword = stashUserPassword;
		this.ignoreUnverifiedSSLPeer
			= ignoreUnverifiedSSLPeer;
		this.commitSha1 = commitSha1;
	}

	public String getStashServerBaseUrl() {
		return stashServerBaseUrl;
	}

	public String getStashUserName() {
		return stashUserName;
	}

	public String getStashUserPassword() {
		return stashUserPassword;
	}
	
	public boolean getIgnoreUnverifiedSSLPeer() {
		return ignoreUnverifiedSSLPeer;
	}
	
	public String getCommitSha1() {
		return commitSha1;
	}

	@SuppressWarnings("rawtypes")
	@Override
	public boolean perform(
			AbstractBuild build, 
			Launcher launcher, 
			BuildListener listener) {

		PrintStream logger = listener.getLogger();

		// exit if Jenkins root URL is not configured. Stash build API 
		// requires valid link to build in CI system.
		if (Jenkins.getInstance().getRootUrl() == null) {
			logger.println(
					"Cannot notify Stash! (Jenkins Root URL not configured)");
			return true;
		}

		String commitSha1 = lookupCommitSha1(build, listener);
		if  (commitSha1 != null) {
			HttpClient client = getHttpClient(logger); 
			NotificationResult result;

			try {
				result = notifyStash(build, commitSha1, client, listener);
				if (result.indicatesSuccess) {
					logger.println(
						"Notified Stash for commit with id " 
								+ commitSha1);
				} else {
					logger.println(
					"Failed to notify Stash for commit "
							+ commitSha1
							+ " (" + result.message + ")");
				}					
            } catch (SSLPeerUnverifiedException e) {
	    		logger.println("SSLPeerUnverifiedException caught while "
    				+ "notifying Stash. Make sure your SSL certificate on "
    				+ "your Stash server is valid or check the "
    				+ " 'Ignore unverifiable SSL certificate' checkbox in the "
    				+ "Stash plugin configuration of this job.");
			} catch (Exception e) {
				logger.println(
						"Caught exception while notifying Stash: " 
						+ e.getMessage());
			} finally {
				client.getConnectionManager().shutdown();
			}			
		} else {
			logger.println(
					"found no commit info");
		}
		return true;
	}
		
	private String lookupCommitSha1(AbstractBuild build, BuildListener listener) {
		if (commitSha1 != null && commitSha1.trim().length() > 0) {
			PrintStream logger = listener.getLogger();
			try {
				EnvVars environment = build.getEnvironment(listener);
				return environment.expand(commitSha1);
			} catch (IOException e) {
				logger.println("Unable to expand commit SHA value " + e.getMessage());
				return null;
			} catch (InterruptedException e) {
				logger.println("Unable to expand commit SHA value " + e.getMessage());
				return null;
			}
		}
		
		// get the sha1 of the commit that was built
		BuildData buildData = (BuildData) build.getAction(BuildData.class);
		if  (buildData != null) {
			return buildData.getLastBuiltRevision().getSha1String();
		}

		return null;
	}

	/**
	 * Returns the HttpClient through which the REST call is made. Uses an
	 * unsafe X509 trust manager in case the user specified a HTTPS URL and
	 * set the ignoreUnverifiedSSLPeer flag.
	 * 
	 * @param logger	the logger to log messages to
	 * @return			the HttpClient
	 */
	private HttpClient getHttpClient(PrintStream logger) {
		HttpClient client = null;
        boolean ignoreUnverifiedSSL = ignoreUnverifiedSSLPeer;
        DescriptorImpl descriptor = getDescriptor();
        if (!ignoreUnverifiedSSL) {
            ignoreUnverifiedSSL = descriptor.isIgnoreUnverifiedSsl();
        }
		if (getStashServerBaseUrl().startsWith("https") 
				&& ignoreUnverifiedSSL) {
			// add unsafe trust manager to avoid thrown
			// SSLPeerUnverifiedException
			try {
				SSLContext sslContext = SSLContext.getInstance("TLS");
				sslContext.init(
						null, 
						new TrustManager[] { new UnsafeX509TrustManager() }, 
						new SecureRandom());
				SSLSocketFactory sslSocketFactory 
					= new SSLSocketFactory(sslContext);
				SchemeRegistry schemeRegistry = new SchemeRegistry();
				schemeRegistry.register(
						new Scheme("https", 443, sslSocketFactory));
				ClientConnectionManager connectionManager 
					= new SingleClientConnManager(schemeRegistry);
				client = new DefaultHttpClient(connectionManager);
			} catch (NoSuchAlgorithmException nsae) {
				logger.println("Couldn't establish SSL context: "
						+ nsae.getMessage());
			} catch (KeyManagementException kme) {
				logger.println("Couldn't initialize SSL context: "
						+ kme.getMessage());
			} finally {
				if (client == null) {
					logger.println("Trying with safe trust manager, instead!");
					client = new DefaultHttpClient();
				}
			}
		} else {
			client = new DefaultHttpClient();
		}
		return client;
	}

    /**
     * Hudson defines a method {@link Builder#getDescriptor()}, which
     * returns the corresponding {@link Descriptor} object.
     *
     * Since we know that it's actually {@link DescriptorImpl}, override
     * the method and give a better return type, so that we can access
     * {@link DescriptorImpl} methods more easily.
     *
     * This is not necessary, but just a coding style preference.
     */
    @Override
    public DescriptorImpl getDescriptor() {
        // see Descriptor javadoc for more about what a descriptor is.
        return (DescriptorImpl)super.getDescriptor();
    }

    @Extension
	public static final class DescriptorImpl 
		extends BuildStepDescriptor<Publisher> {

        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use <tt>transient</tt>.
         */

        private String stashUser;
        private Secret stashPassword;
        private String stashRootUrl;
        private boolean ignoreUnverifiedSsl;

        public DescriptorImpl() {
            load();
        }

        public String getStashUser() {
        	if ((stashUser != null) && (stashUser.trim().equals(""))) {
        		return null;
        	} else {
	            return stashUser;
        	}
        }

        public Secret getStashPassword() {
            return stashPassword;
        }

        public String getEncryptedStashPassword() {
            if (stashPassword != null)
                return stashPassword.getEncryptedValue();
            else
                return null;
        }

        public String getStashRootUrl() {
        	if ((stashRootUrl == null) || (stashRootUrl.trim().equals(""))) {
        		return null;
        	} else {
	            return stashRootUrl;
        	}
        }

        public boolean isIgnoreUnverifiedSsl() {
            return ignoreUnverifiedSsl;
        }

        public FormValidation doCheckStashServerBaseUrl(
					@QueryParameter String value) 
				throws IOException, ServletException {

			// calculate effective url from global and local config
			String url = value;
			if ((url != null) && (!url.trim().equals(""))) {
				url = url.trim();
			} else {
				url = stashRootUrl != null ? stashRootUrl.trim() : null;
			}

			if ((url == null) || url.equals("")) {
				return FormValidation.error(
						"Please specify a valid URL here or in the global " 
						+ "configuration");
			} else {
				try {
					new URL(url);
					return FormValidation.ok();
				} catch (Exception e) {
					return FormValidation.error(
						"Please specify a valid URL here or in the global "
						+ "configuration!");
				}
			}
		}

		public FormValidation doCheckStashUserName(@QueryParameter String value)
				throws IOException, ServletException {

			if (value.trim().equals("") 
					&& ((stashUser == null) || stashUser.trim().equals(""))) {
				return FormValidation.error(
						"Please specify a user name here or in the global "
						+ "configuration!");
			} else {
				return FormValidation.ok();
			}
		}

		public FormValidation doCheckStashUserPassword(
					@QueryParameter String value) 
				throws IOException, ServletException {

			if (value.trim().equals("") 
					&& ((stashPassword == null) 
						|| stashPassword.getPlainText().trim().equals(""))) { 
				return FormValidation.warning(
						"You should use a non-empty password here or in the "
						+ "global configuration!");
			} else {
				return FormValidation.ok();
			}
		}

		@SuppressWarnings("rawtypes")
		public boolean isApplicable(Class<? extends AbstractProject> aClass) {
			return true;
		}

		public String getDisplayName() {
			return "Notify Stash Instance";
		}

		@Override
		public boolean configure(
				StaplerRequest req, 
				JSONObject formData) throws FormException {

            // to persist global configuration information,
            // set that to properties and call save().
            stashUser = formData.getString("stashUser");
            stashPassword = Secret.fromString(formData.getString("stashPassword"));
            stashRootUrl = formData.getString("stashRootUrl");
            ignoreUnverifiedSsl = formData.getBoolean("ignoreUnverifiedSsl");
			save();
			return super.configure(req,formData);
		}
	}
	
	// non-public members ------------------------------------------------------
	
	/**
	 * Notifies the configured Stash server by POSTing the build results 
	 * to the Stash build API.
	 * 
	 * @param build			the build to notify Stash of
	 * @param commitSha1	the SHA1 of the built commit
	 * @param client		the HTTP client with which to execute the request
	 * @param listener		the build listener for logging
	 */
	@SuppressWarnings("rawtypes")
	private NotificationResult notifyStash(
			final AbstractBuild build,
			final String commitSha1,
			final HttpClient client, 
			final BuildListener listener) throws Exception {
		
		HttpPost req = createRequest(build, commitSha1);
		HttpResponse res = client.execute(req);
		if (res.getStatusLine().getStatusCode() != 204) {
			return NotificationResult.newFailure(
					EntityUtils.toString(res.getEntity()));
		} else {
			return NotificationResult.newSuccess();
		}
	}
	
	/**
	 * Returns the HTTP POST request ready to be sent to the Stash build API for
	 * the given build and change set. 
	 * 
	 * @param build			the build to notify Stash of
	 * @param commitSha1	the SHA1 of the commit that was built
	 * @return				the HTTP POST request to the Stash build API
	 */
	@SuppressWarnings("rawtypes")
	private HttpPost createRequest(
			final AbstractBuild build,
			final String commitSha1) throws Exception {
        String url = stashServerBaseUrl;
        String username = stashUserName;
        String pwd = stashUserPassword;
        DescriptorImpl descriptor = getDescriptor();

        if ("".equals(url) || url == null)
            url = descriptor.getStashRootUrl();
        if ("".equals(username) || username == null)
            username = descriptor.getStashUser();
        if ("".equals(pwd) || pwd == null)
            pwd = descriptor.getStashPassword().getPlainText();
		
		HttpPost req = new HttpPost(
				url
				+ "/rest/build-status/1.0/commits/" 
				+ commitSha1);
		
		req.addHeader(BasicScheme.authenticate(
				new UsernamePasswordCredentials(
						username,
						pwd),
				"UTF-8", 
				false));
		
		req.addHeader("Content-type", "application/json");		
		req.setEntity(newStashBuildNotificationEntity(build));
				
		return req;
	}
	
	/**
	 * Returns the HTTP POST entity body with the JSON representation of the
	 * builds result to be sent to the Stash build API.
	 * 
	 * @param build			the build to notify Stash of
	 * @return				HTTP entity body for POST to Stash build API
	 */
	@SuppressWarnings("rawtypes")
	private HttpEntity newStashBuildNotificationEntity(final AbstractBuild build)
            throws Exception {

        JSONObject json = new JSONObject();

        if ((build.getResult() == null) 
        		|| (!build.getResult().equals(Result.SUCCESS))) {
            json.put("state", "FAILED");
        } else {
            json.put("state", "SUCCESSFUL");
        }

        json.put(
        		"key",
        		StringEscapeUtils.escapeJavaScript(
        				build.getProject().getName()) + "-" + 
        				build.getNumber() + "-" + 
        				Jenkins.getInstance().getRootUrl());

        // This is to replace the odd character Jenkins injects to separate 
        // nested jobs, especially when using the Cloudbees Folders plugin. 
        // These characters cause Stash to throw up.
        String fullName = StringEscapeUtils.
                escapeJavaScript(build.getFullDisplayName()).
                replaceAll("\\\\u00BB", "\\/");
        json.put("name", fullName);

        json.put("description",
                "built by Jenkins @ ".concat(Jenkins.getInstance().getRootUrl()));
        json.put("url", Jenkins.getInstance().getRootUrl().concat(build.getUrl()));
        return new StringEntity(json.toString());
	}
}
