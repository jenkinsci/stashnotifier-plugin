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
import hudson.Extension;
import hudson.Launcher;
import hudson.ProxyConfiguration;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Result;
import hudson.plugins.git.util.BuildData;
import hudson.plugins.git.Revision;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.servlet.ServletException;

import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;

import org.apache.http.auth.AuthScope;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;

/**
 * Notifies a configured Atlassian Stash server instance of build results
 * through the Stash build API.
 * <p>
 * Only basic authentication is supported at the moment.
 */
public class StashNotifier extends Notifier {
	
	public static final int MAX_FIELD_LENGTH = 255;
	public static final int MAX_URL_FIELD_LENGTH = 450;

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
	
	/** if true, previous builds will be set on SUCCESS and description edited. */
	private final boolean cleanupBuildsOnSuccess;

	/** specify project key manually */
	private final String projectKey;

	/** append parent project key to key formation */
	private final boolean prependParentProjectKey;

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
			boolean includeBuildNumberInKey,
			boolean cleanupBuildsOnSuccess,
			String projectKey,
			boolean prependParentProjectKey) {
		this.stashServerBaseUrl = stashServerBaseUrl.endsWith("/")
                ? stashServerBaseUrl.substring(0, stashServerBaseUrl.length()-1)
                : stashServerBaseUrl;
		this.stashUserName = stashUserName;
		this.stashUserPassword = Secret.fromString(stashUserPassword);
		this.ignoreUnverifiedSSLPeer
			= ignoreUnverifiedSSLPeer;
		this.commitSha1 = commitSha1;
		this.includeBuildNumberInKey = includeBuildNumberInKey;
		this.cleanupBuildsOnSuccess = cleanupBuildsOnSuccess;
		this.projectKey = projectKey;
		this.prependParentProjectKey = prependParentProjectKey;
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

    public String getProjectKey() {
        return projectKey;
    }

    public boolean getPrependParentProjectKey() {
        return prependParentProjectKey;
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
			Revision lastBuiltRevision = buildData.getLastBuiltRevision();
			if (lastBuiltRevision == null) {
				continue;
			}
			String lastBuiltSha1 = lastBuiltRevision.getSha1String();

			// Should never be null, but may be blank
			if (!lastBuiltSha1.isEmpty()) {
				sha1s.add(lastBuiltSha1);
			}

			// This might be different than the lastBuiltSha1 if using "Merge before build"
			String markedSha1 = buildData.lastBuild.getMarked().getSha1String();

			// Should never be null, but may be blank
			if (!markedSha1.isEmpty()) {
				sha1s.add(markedSha1);
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
	private HttpClient getHttpClient(PrintStream logger) throws Exception {
        String stashServer = stashServerBaseUrl;
        DescriptorImpl descriptor = getDescriptor();
        if ("".equals(stashServer) || stashServer == null) {
            stashServer = descriptor.getStashRootUrl();
        }

        URL url = new URL(stashServer);
        HttpClientBuilder builder = HttpClientBuilder.create();
        if (ignoreUnverifiedSSLPeer && url.getProtocol().equals("https")) {
			// add unsafe trust manager to avoid thrown
			// SSLPeerUnverifiedException
			try {
				TrustStrategy easyStrategy = new TrustStrategy() {
				    public boolean isTrusted(X509Certificate[] chain, String authType)
				            throws CertificateException {
				        return true;
				    }
				};

				SSLContext sslContext = SSLContexts.custom()
						.loadTrustMaterial(null, easyStrategy)
						.useTLS().build();
				SSLConnectionSocketFactory sslConnSocketFactory
						= new SSLConnectionSocketFactory(sslContext,
						SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
				builder.setSSLSocketFactory(sslConnSocketFactory);

				Registry<ConnectionSocketFactory> registry
						= RegistryBuilder.<ConnectionSocketFactory>create()
							.register("https", sslConnSocketFactory)
							.build();

				HttpClientConnectionManager ccm
						= new BasicHttpClientConnectionManager(registry);

				builder.setConnectionManager(ccm);
			} catch (NoSuchAlgorithmException nsae) {
				logger.println("Couldn't establish SSL context:");
				nsae.printStackTrace(logger);
			} catch (KeyManagementException kme) {
				logger.println("Couldn't initialize SSL context:");
				kme.printStackTrace(logger);
			} catch (KeyStoreException kse) {
				logger.println("Couldn't initialize SSL context:");
				kse.printStackTrace(logger);
			}
        }

        // Configure the proxy, if needed
        // Using the Jenkins methods handles the noProxyHost settings
        ProxyConfiguration proxyConfig = Jenkins.getInstance().proxy;
        if (proxyConfig != null) {
            Proxy proxy = proxyConfig.createProxy(url.getHost());
            if (proxy != null && proxy.type() == Proxy.Type.HTTP) {
                SocketAddress addr = proxy.address();
                if (addr != null && addr instanceof InetSocketAddress) {
                    InetSocketAddress proxyAddr = (InetSocketAddress) addr;
                    HttpHost proxyHost = new HttpHost(proxyAddr.getAddress().getHostAddress(), proxyAddr.getPort());
                    builder = builder.setProxy(proxyHost);

                    String proxyUser = proxyConfig.getUserName();
                    if (proxyUser != null) {
                        String proxyPass = proxyConfig.getPassword();
                        CredentialsProvider cred = new BasicCredentialsProvider();
                        cred.setCredentials(new AuthScope(proxyHost),
                                new UsernamePasswordCredentials(proxyUser, proxyPass));
                        builder = builder
                                .setDefaultCredentialsProvider(cred)
                                .setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
                    }
                }
            }
        }

        return builder.build();
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
		private String projectKey;
		private boolean prependParentProjectKey;
		private boolean cleanupBuildsOnSuccess;

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

		public String getProjectKey() {
			return projectKey;
		}

		public boolean isPrependParentProjectKey() {
			return prependParentProjectKey;
		}
		
		public boolean isCleanupBuildsOnSuccess() {
			return cleanupBuildsOnSuccess;
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
            if (formData.has("projectKey")) {
                projectKey
                        = formData.getString("projectKey");
            }
            prependParentProjectKey
                = formData.getBoolean("prependParentProjectKey");
            cleanupBuildsOnSuccess = formData.getBoolean("cleanupBuildsOnSuccess");

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
		HttpClient client = getHttpClient(logger);
		
		try {
			// first collect all existing builds if cleanup old previous builds is required
			if (cleanupBuildsOnSuccess && StashBuildState.SUCCESSFUL.equals(state)) {
				logger.println("Cleaning previous builds for " + commitSha1);
				HttpGet req = createGetRequest(commitSha1);
				HttpResponse res = client.execute(req);
				if (res.getStatusLine().getStatusCode() != 200) {
					return NotificationResult.newFailure(
							EntityUtils.toString(res.getEntity()));
				} else {
					// TODO gather all statuses being verifying isLastPage and getting the next page
					// however it is extremely unlikely that a commit has that many builds on it
					JSONObject buildStatusesPage = JSONObject.fromObject(EntityUtils.toString(res.getEntity()));
					JSONArray buildStatuses = buildStatusesPage.getJSONArray("values");
					@SuppressWarnings("unchecked")
					Iterator<JSONObject> iterator = buildStatuses.iterator();
					while(iterator.hasNext()) {
						JSONObject buildStatus = iterator.next();
						// only change status for unsuccessful builds
						String buildState = buildStatus.getString("state");
						if (!StashBuildState.SUCCESSFUL.name().equalsIgnoreCase(buildState)) {
							HttpEntity stashBuildNotificationEntity	= newStashBuildNotificationEntity(
									StashBuildState.SUCCESSFUL, 
									buildStatus.getString("key"),
									"(" + buildState.toLowerCase() + ") " + buildStatus.getString("name"), 
									"Status changed by Jenkins @ " + Jenkins.getInstance().getRootUrl(), 
									buildStatus.getString("url"));
							HttpPost buildStatusReq = createPostRequest(stashBuildNotificationEntity, commitSha1);
							HttpResponse buildStatusRes = client.execute(buildStatusReq);
							if (buildStatusRes.getStatusLine().getStatusCode() != 204) {
								return NotificationResult.newFailure(
										EntityUtils.toString(buildStatusRes.getEntity()));
							}
						}
					}					
				}
			}
			
			HttpEntity stashBuildNotificationEntity
				= newStashBuildNotificationEntity(build, state, listener);
			HttpPost req = createPostRequest(stashBuildNotificationEntity, commitSha1);
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
	 * Returns the HTTP GET request ready to be sent to the Stash build API for
	 * the given build and change set.
	 *
	 * @param commitSha1	the SHA1 of the commit that was built
	 * @return				the HTTP GET request to the Stash build API
	 */
	private HttpGet createGetRequest(final String commitSha1) {
		HttpGet req = new HttpGet();
		prepareRequest(req, commitSha1);
		return req;
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
	private HttpPost createPostRequest(
			final HttpEntity stashBuildNotificationEntity,
			final String commitSha1) {
		HttpPost req = new HttpPost();
		prepareRequest(req, commitSha1);
		req.setEntity(stashBuildNotificationEntity);
		return req;
	}
	
	/**
	 * Prepares an HTTP request to be sent to the Stash build API for
	 * the given build and change set.
	 *
	 * @param commitSha1	the SHA1 of the commit that was built
	 */
	private void prepareRequest(final HttpRequestBase base,
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

        base.setURI(URI.create(url
				+ "/rest/build-status/1.0/commits/"
				+ commitSha1));

		base.addHeader(BasicScheme.authenticate(
				new UsernamePasswordCredentials(
						username,
						pwd),
				"UTF-8",
				false));

		base.addHeader("Content-type", "application/json");
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
			final StashBuildState state,
            BuildListener listener) throws UnsupportedEncodingException {

		return newStashBuildNotificationEntity(
				state, 
				getBuildKey(build, listener), 
				
				// This is to replace the odd character Jenkins injects to separate 
		        // nested jobs, especially when using the Cloudbees Folders plugin. 
		        // These characters cause Stash to throw up.
		        StringEscapeUtils.escapeJavaScript(build.getFullDisplayName()).
                	replaceAll("\\\\u00BB", "\\/"), 
                	
                getBuildDescription(build, state), 
                Jenkins.getInstance().getRootUrl().concat(build.getUrl()));
	}
	
	/**
	 * Returns the HTTP POST entity body with the JSON representation of the
	 * builds result to be sent to the Stash build API.
	 *
	 * @return				HTTP entity body for POST to Stash build API
	 */
	private HttpEntity newStashBuildNotificationEntity(
			final StashBuildState state,
			final String key,
			final String name,
			final String description,
			final String url) throws UnsupportedEncodingException {
		JSONObject json = new JSONObject();
        json.put("state", state.name());
        json.put("key", abbreviate(key, MAX_FIELD_LENGTH));
        json.put("name", abbreviate(name, MAX_FIELD_LENGTH));
		json.put("description", abbreviate(description, MAX_FIELD_LENGTH));
		json.put("url", abbreviate(url, MAX_URL_FIELD_LENGTH));
        return new StringEntity(json.toString(), "UTF-8");
	}

	private static String abbreviate(String text, int maxWidth) {
		if (text == null) {
			return null;
		}
		if (maxWidth < 4) {
			throw new IllegalArgumentException("Minimum abbreviation width is 4");
		}
		if (text.length() <= maxWidth) {
			return text;
		}
		return text.substring(0, maxWidth - 3) + "...";
	}

	/**
	 * Return the old-fashion build key
	 *
	 * @param  build the build to notify Stash of
	 * @return default build key
	 */
	private String getDefaultBuildKey(final AbstractBuild<?, ?> build) {
		StringBuilder key = new StringBuilder();

		key.append(build.getProject().getName());
		if (includeBuildNumberInKey) {
			key.append('-').append(build.getNumber());
		}
		key.append('-').append(Jenkins.getInstance().getRootUrl());

		return key.toString();
	}

		/**
         * Returns the build key used in the Stash notification. Includes the
         * build number depending on the user setting.
         *
         * @param 	build	the build to notify Stash of
         * @return	the build key for the Stash notification
         */
	private String getBuildKey(final AbstractBuild<?, ?> build,
							   BuildListener listener) {

		StringBuilder key = new StringBuilder();

		if (prependParentProjectKey){
			if (null != build.getParent().getParent()) {
				key.append(build.getParent().getParent().getFullName()).append('-');
			}
		}

		String overriddenKey = (projectKey != null && projectKey.trim().length() > 0) ? projectKey : getDescriptor().getProjectKey();

		if (overriddenKey != null && overriddenKey.trim().length() > 0) {
			PrintStream logger = listener.getLogger();
			try {
				EnvVars environment = build.getEnvironment(listener);
				key.append(environment.expand(projectKey));
			} catch (IOException e) {
				logger.println("Cannot expand build key from parameter. Processing with default build key");
				e.printStackTrace(logger);
				key.append(getDefaultBuildKey(build));
			} catch (InterruptedException e) {
				logger.println("Cannot expand build key from parameter. Processing with default build key");
				e.printStackTrace(logger);
				key.append(getDefaultBuildKey(build));
			}
		} else {
			key.append(getDefaultBuildKey(build));
		}

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
