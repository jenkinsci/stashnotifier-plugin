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
import hudson.ProxyConfiguration;
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
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
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
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.regex.Pattern;

import jenkins.model.Jenkins;

/**
 * Notifies a configured Atlassian Stash server instance of build results
 * through the Stash build API.
 * <p>
 * Only basic authentication is supported at the moment.
 */
public class StashNotifier extends Notifier {
	
	// attributes --------------------------------------------------------------

	/** base url of Stash server, e. g. <tt>http://localhost:7990</tt>. */
	private final String stashServerBaseUrl;
	
	/** name of Stash user for authentication with Stash build API. */
	private final String stashUserName;
	
	/** password of Stash user for authentication with Stash build API. */
	private final Secret stashUserPassword;
	
	/** if true, ignore exception thrown in case of an unverified SSL peer. */
	private final boolean ignoreUnverifiedSSLPeer;

	/** specify the commit from config */
	private final String commitSha1;
	
	/** if true, the build number is included in the Stash notification. */
	private final boolean includeBuildNumberInKey;
	
	// public members ----------------------------------------------------------

	public BuildStepMonitor getRequiredMonitorService() {
		return BuildStepMonitor.NONE;
	}

	@DataBoundConstructor
	public StashNotifier(
			String stashServerBaseUrl,
			String stashUserName,
			String stashUserPassword,
			boolean ignoreUnverifiedSSLPeer,
			String commitSha1,
			boolean includeBuildNumberInKey) {
		this.stashServerBaseUrl = stashServerBaseUrl.endsWith("/")
                ? stashServerBaseUrl.substring(0, stashServerBaseUrl.length()-1)
                : stashServerBaseUrl;
		this.stashUserName = stashUserName;
		this.stashUserPassword = Secret.fromString(stashUserPassword);
		this.ignoreUnverifiedSSLPeer
			= ignoreUnverifiedSSLPeer;
		this.commitSha1 = commitSha1;
		this.includeBuildNumberInKey = includeBuildNumberInKey;
	}

	public String getStashServerBaseUrl() {
		return stashServerBaseUrl;
	}

	public String getStashUserName() {
		return stashUserName;
	}

	public String getStashUserPassword() {
		return stashUserPassword.getEncryptedValue();
	}
	
	public boolean getIgnoreUnverifiedSSLPeer() {
		return ignoreUnverifiedSSLPeer;
	}
	
	public String getCommitSha1() {
		return commitSha1;
	}

	public boolean getIncludeBuildNumberInKey() {
		return includeBuildNumberInKey;
	}
	
	@Override
	public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {
		return processJenkinsEvent(build, listener, StashBuildState.INPROGRESS);
	}
	
	@Override
	public boolean perform(
			AbstractBuild<?, ?> build, 
			Launcher launcher, 
			BuildListener listener) {
		
		if ((build.getResult() == null) 
				|| (!build.getResult().equals(Result.SUCCESS))) {
			return processJenkinsEvent(
					build, listener, StashBuildState.FAILED);
		} else {
			return processJenkinsEvent(
					build, listener, StashBuildState.SUCCESSFUL);
		}
	}

	/**
	 * Processes the Jenkins events triggered before and after the build and
	 * initiates the Stash notification.
	 * 
	 * @param build		the build to notify Stash of
	 * @param listener	the Jenkins build listener
	 * @param state		the state of the build (in progress, success, failed)
	 * @return			always true in order not to abort the Job in case of
	 * 					notification failures
	 */
	private boolean processJenkinsEvent(
			final AbstractBuild<?, ?> build, 
			final BuildListener listener, 
			final StashBuildState state) {
		
		PrintStream logger = listener.getLogger();

		// exit if Jenkins root URL is not configured. Stash build API 
		// requires valid link to build in CI system.
		if (Jenkins.getInstance().getRootUrl() == null) {
			logger.println(
					"Cannot notify Stash! (Jenkins Root URL not configured)");
			return true;
		}

		Collection<String> commitSha1s = lookupCommitSha1s(build, listener);
		for  (String commitSha1 : commitSha1s) {
			try {
				NotificationResult result 
					= notifyStash(logger, build, commitSha1, listener, state);
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
				logger.println("Caught exception while notifying Stash with id " 
					+ commitSha1);
				e.printStackTrace(logger);
			}			
		}
		if (commitSha1s.isEmpty()) {
			logger.println("found no commit info");
		}
		return true;
	}

	private Collection<String> lookupCommitSha1s(
			@SuppressWarnings("rawtypes") AbstractBuild build,
			BuildListener listener) {
		
		if (commitSha1 != null && commitSha1.trim().length() > 0) {
			PrintStream logger = listener.getLogger();
			try {
				EnvVars environment = build.getEnvironment(listener);
				return Arrays.asList(environment.expand(commitSha1));
			} catch (IOException e) {
				logger.println("Unable to expand commit SHA value");
				e.printStackTrace(logger);
				return Arrays.asList();
			} catch (InterruptedException e) {
				logger.println("Unable to expand commit SHA value");
				e.printStackTrace(logger);
				return Arrays.asList();
			}
		}

		// Use a set to remove duplicates
		Collection<String> sha1s = new HashSet<String>();
		// MultiSCM may add multiple BuildData actions for each SCM, but we are covered in any case
		for (BuildData buildData : build.getActions(BuildData.class)) {
			// get the sha1 of the commit that was built
			String sha1 = buildData.getLastBuiltRevision().getSha1String();
			// Should never be null, but may be blank
			if (!sha1.isEmpty()) {
				sha1s.add(sha1);
			}
		}
		return sha1s;
	}

	/**
	 * Returns the HttpClient through which the REST call is made. Uses an
	 * unsafe TrustStrategy in case the user specified a HTTPS URL and
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
				TrustStrategy easyStrategy = new TrustStrategy() {
				    public boolean isTrusted(X509Certificate[] chain, String authType)
				            throws CertificateException {
				        return true;
				    }
				};

				SSLSocketFactory sslSocketFactory 
					= new SSLSocketFactory(easyStrategy);
				SchemeRegistry schemeRegistry = new SchemeRegistry();
				schemeRegistry.register(
						new Scheme("https", 443, sslSocketFactory));
				ClientConnectionManager connectionManager 
					= new SingleClientConnManager(schemeRegistry);
				client = new DefaultHttpClient(connectionManager);
			} catch (NoSuchAlgorithmException nsae) {
				logger.println("Couldn't establish SSL context:");
				nsae.printStackTrace(logger);
			} catch (KeyManagementException kme) {
				logger.println("Couldn't initialize SSL context:");
				kme.printStackTrace(logger);
			} catch (KeyStoreException kse) {
				logger.println("Couldn't initialize SSL context:");
				kse.printStackTrace(logger);
			} catch (UnrecoverableKeyException uke) {
				logger.println("Couldn't initialize SSL context:");
				uke.printStackTrace(logger);
			} finally {
				if (client == null) {
					logger.println("Trying with safe trust manager, instead!");
					client = new DefaultHttpClient();
				}
			}
		} else {
			client = new DefaultHttpClient();
		}
		
		ProxyConfiguration proxy = Jenkins.getInstance().proxy;
		if(proxy != null && !proxy.name.isEmpty() && !proxy.name.startsWith("http") && !isHostOnNoProxyList(proxy)){
			SchemeRegistry schemeRegistry = client.getConnectionManager().getSchemeRegistry();
			schemeRegistry.register(new Scheme("http", proxy.port, new PlainSocketFactory()));
			client.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, new HttpHost(proxy.name, proxy.port));
		}
		
		return client;
	}
	
	/**
	 * Returns whether or not the stash host is on the noProxy list
	 * as defined in the Jenkins proxy settings
	 * 
	 * @param host     the stash URL
	 * @param proxy    the ProxyConfiguration
	 * @return         whether or not the host is on the noProxy list
	 */
	private boolean isHostOnNoProxyList(ProxyConfiguration proxy) {
	    String host = getStashServerBaseUrl();
	    if ("".equals(host) || host == null) {
	        DescriptorImpl descriptor = getDescriptor();
	        host = descriptor.getStashRootUrl();
	    }
	    if (host != null && proxy.noProxyHost != null) {
            for (Pattern p : ProxyConfiguration.getNoProxyHostPatterns(proxy.noProxyHost)) {
                if (p.matcher(host).matches()) {
                    return true;
                }
            }
	    }
	    return false;
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
        private boolean includeBuildNumberInKey;

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

        public boolean isIncludeBuildNumberInKey() {
            return includeBuildNumberInKey;
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
            stashUser 
            	= formData.getString("stashUser");
            stashPassword 
            	= Secret.fromString(formData.getString("stashPassword"));
            stashRootUrl 
            	= formData.getString("stashRootUrl");
            ignoreUnverifiedSsl 
            	= formData.getBoolean("ignoreUnverifiedSsl");
            includeBuildNumberInKey 
            	= formData.getBoolean("includeBuildNumberInKey");
			save();
			return super.configure(req,formData);
		}
	}
	
	// non-public members ------------------------------------------------------
	
	/**
	 * Notifies the configured Stash server by POSTing the build results 
	 * to the Stash build API.
	 * 
	 * @param logger		the logger to use
	 * @param build			the build to notify Stash of
	 * @param commitSha1	the SHA1 of the built commit
	 * @param client		the HTTP client with which to execute the request
	 * @param listener		the build listener for logging
	 * @param state			the state of the build as defined by the Stash API.
	 */
	private NotificationResult notifyStash(
			final PrintStream logger, 
			final AbstractBuild<?, ?> build,
			final String commitSha1,
			final BuildListener listener,
			final StashBuildState state) throws Exception {
		HttpEntity stashBuildNotificationEntity 
			= newStashBuildNotificationEntity(build, state);
		HttpPost req = createRequest(stashBuildNotificationEntity, commitSha1);
		HttpClient client = getHttpClient(logger);
		try {
			HttpResponse res = client.execute(req);
			if (res.getStatusLine().getStatusCode() != 204) {
				return NotificationResult.newFailure(
						EntityUtils.toString(res.getEntity()));
			} else {
				return NotificationResult.newSuccess();
			}
		} finally {
			client.getConnectionManager().shutdown();
		}
	}

	/**
	 * Returns the HTTP POST request ready to be sent to the Stash build API for
	 * the given build and change set. 
	 * 
	 * @param stashBuildNotificationEntity	a entity containing the parameters 
	 * 										for Stash
	 * @param commitSha1	the SHA1 of the commit that was built
	 * @return				the HTTP POST request to the Stash build API
	 */
	private HttpPost createRequest(
			final HttpEntity stashBuildNotificationEntity, 
			final String commitSha1) {
		
		String url = stashServerBaseUrl;
        String username = stashUserName;
        String pwd = Secret.toString(stashUserPassword);
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
		req.setEntity(stashBuildNotificationEntity);
				
		return req;
	}
	
	/**
	 * Returns the HTTP POST entity body with the JSON representation of the
	 * builds result to be sent to the Stash build API.
	 * 
	 * @param build			the build to notify Stash of
	 * @return				HTTP entity body for POST to Stash build API
	 */
	private HttpEntity newStashBuildNotificationEntity(
			final AbstractBuild<?, ?> build, 
			final StashBuildState state) throws UnsupportedEncodingException {
		
		JSONObject json = new JSONObject();

        json.put("state", state.name());

        json.put("key", getBuildKey(build));

        // This is to replace the odd character Jenkins injects to separate 
        // nested jobs, especially when using the Cloudbees Folders plugin. 
        // These characters cause Stash to throw up.
        String fullName = StringEscapeUtils.
                escapeJavaScript(build.getFullDisplayName()).
                replaceAll("\\\\u00BB", "\\/");
        json.put("name", fullName);

        json.put("description", getBuildDescription(build, state));
        json.put("url", Jenkins.getInstance()
        		.getRootUrl().concat(build.getUrl()));
        
        return new StringEntity(json.toString());
	}

	/**
	 * Returns the build key used in the Stash notification. Includes the 
	 * build number depending on the user setting.
	 * 
	 * @param 	build	the build to notify Stash of
	 * @return	the build key for the Stash notification
	 */
	private String getBuildKey(final AbstractBuild<?, ?> build) {
		StringBuilder key = new StringBuilder();
		key.append(build.getProject().getName());
        if (includeBuildNumberInKey 
        		|| getDescriptor().isIncludeBuildNumberInKey()) {
			key.append('-').append(build.getNumber());
		}
		key.append('-').append(Jenkins.getInstance().getRootUrl());
		return StringEscapeUtils.escapeJavaScript(key.toString());
	}

	/**
	 * Returns the description of the build used for the Stash notification. 
	 * Uses the build description provided by the Jenkins job, if available.
	 * 
	 * @param build		the build to be described
	 * @param state		the state of the build
	 * @return			the description of the build
	 */
	private String getBuildDescription(
			final AbstractBuild<?, ?> build, 
			final StashBuildState state) {
		
		if (build.getDescription() != null 
				&& build.getDescription().trim().length() > 0) {
			
			return build.getDescription();
		} else {
			switch (state) {
			case INPROGRESS:
	            return "building on Jenkins @ " 
					+ Jenkins.getInstance().getRootUrl();
			default:
	            return "built by Jenkins @ " 
	            	+ Jenkins.getInstance().getRootUrl();
			}
		}
	}
}
