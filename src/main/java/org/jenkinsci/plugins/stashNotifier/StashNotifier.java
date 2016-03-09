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

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.*;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.Extension;
import hudson.Launcher;
import hudson.ProxyConfiguration;
import hudson.model.*;
import hudson.plugins.git.Revision;
import hudson.plugins.git.util.BuildData;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import jenkins.model.JenkinsLocationConfiguration;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.*;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.AncestorInPath;
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
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

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

	/** The id of the credentials to use. */
	private String credentialsId;

	/** if true, ignore exception thrown in case of an unverified SSL peer. */
	private final boolean ignoreUnverifiedSSLPeer;

	/** specify the commit from config */
	private final String commitSha1;

	/** if true, the build number is included in the Stash notification. */
	private final boolean includeBuildNumberInKey;

	/** specify project key manually */
	private final String projectKey;

	/** append parent project key to key formation */
	private final boolean prependParentProjectKey;

	/** whether to send INPROGRESS notification at the build start */
	private final boolean disableInprogressNotification;

	private JenkinsLocationConfiguration globalConfig = new JenkinsLocationConfiguration();

// public members ----------------------------------------------------------

	public BuildStepMonitor getRequiredMonitorService() {
		return BuildStepMonitor.NONE;
	}

	@DataBoundConstructor
	public StashNotifier(
			String stashServerBaseUrl,
			String credentialsId,
			boolean ignoreUnverifiedSSLPeer,
			String commitSha1,
			boolean includeBuildNumberInKey,
			String projectKey,
			boolean prependParentProjectKey,
			boolean disableInprogressNotification
	) {


		this.stashServerBaseUrl = stashServerBaseUrl.endsWith("/")
				? stashServerBaseUrl.substring(0, stashServerBaseUrl.length() - 1)
				: stashServerBaseUrl;
		this.credentialsId = credentialsId;
		this.ignoreUnverifiedSSLPeer
				= ignoreUnverifiedSSLPeer;
		this.commitSha1 = commitSha1;
		this.includeBuildNumberInKey = includeBuildNumberInKey;
		this.projectKey = projectKey;
		this.prependParentProjectKey = prependParentProjectKey;
		this.disableInprogressNotification = disableInprogressNotification;
	}

	public boolean isDisableInprogressNotification() {
		return disableInprogressNotification;
	}

	public String getCredentialsId() {
		return credentialsId;
	}

	public String getStashServerBaseUrl() {
		return stashServerBaseUrl;
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
		    return disableInprogressNotification || processJenkinsEvent(build, listener, StashBuildState.INPROGRESS);
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
	 * Provide a fallback for getting the instance's root URL
	 *
	 * @return Root URL contained in the global config
	 */
	private String getRootUrl() {
		return (Jenkins.getInstance().getRootUrl() != null) ? Jenkins.getInstance().getRootUrl() : globalConfig.getUrl();
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
		if (getRootUrl() == null) {
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

    protected Collection<String> lookupCommitSha1s(
			@SuppressWarnings("rawtypes") AbstractBuild build,
			BuildListener listener) {

		if (commitSha1 != null && commitSha1.trim().length() > 0) {
			PrintStream logger = listener.getLogger();
			try {
				return Arrays.asList(TokenMacro.expandAll(build, listener, commitSha1));
			} catch (IOException e) {
				logger.println("Unable to expand commit SHA value");
				e.printStackTrace(logger);
				return Arrays.asList();
			} catch (InterruptedException e) {
				logger.println("Unable to expand commit SHA value");
				e.printStackTrace(logger);
				return Arrays.asList();
			} catch (MacroEvaluationException e) {
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
	 * @param logger    the logger to log messages to
	 * @param build
	 * @return			the HttpClient
	 */
	protected HttpClient getHttpClient(PrintStream logger, AbstractBuild<?, ?> build) throws Exception {
        boolean ignoreUnverifiedSSL = ignoreUnverifiedSSLPeer;
        String stashServer = stashServerBaseUrl;
        DescriptorImpl descriptor = getDescriptor();

        CertificateCredentials certificateCredentials = getCredentials(CertificateCredentials.class, build.getProject());

        if ("".equals(stashServer) || stashServer == null) {
            stashServer = descriptor.getStashRootUrl();
        }
        if (!ignoreUnverifiedSSL) {
            ignoreUnverifiedSSL = descriptor.isIgnoreUnverifiedSsl();
        }

        URL url = new URL(stashServer);
        HttpClientBuilder builder = HttpClientBuilder.create();
        if (url.getProtocol().equals("https")
                && (ignoreUnverifiedSSL || certificateCredentials instanceof CertificateCredentials)) {
			// add unsafe trust manager to avoid thrown
			// SSLPeerUnverifiedException
			try {
				SSLConnectionSocketFactory sslConnSocketFactory
						= new SSLConnectionSocketFactory(buildSslContext(ignoreUnverifiedSSL,certificateCredentials),
                        ignoreUnverifiedSSL ? SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER : null);
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
                        BasicCredentialsProvider cred = new BasicCredentialsProvider();
                        cred.setCredentials(new AuthScope(proxyHost),
                                new org.apache.http.auth.UsernamePasswordCredentials(proxyUser, proxyPass));
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
     * Helper in place to allow us to define out HttpClient SSL context
     *
     * @param ignoreUnverifiedSSL
     * @param credentials
     * @return
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws KeyManagementException
     */
	private SSLContext buildSslContext(boolean ignoreUnverifiedSSL, Credentials credentials) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

		SSLContextBuilder customContext = SSLContexts.custom();
		if (credentials instanceof CertificateCredentials) {
			customContext  = customContext.loadKeyMaterial(((CertificateCredentials) credentials).getKeyStore(),((CertificateCredentials) credentials).getPassword().getPlainText().toCharArray());
		}
		if (ignoreUnverifiedSSL) {
			TrustStrategy easyStrategy = new TrustStrategy() {
				public boolean isTrusted(X509Certificate[] chain, String authType)
						throws CertificateException {
					return true;
				}
			};
			customContext = customContext
					.loadTrustMaterial(null, easyStrategy);
		}
		return customContext.useTLS().build();
}

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

        private String credentialsId;
        private String stashRootUrl;
        private boolean ignoreUnverifiedSsl;
        private boolean includeBuildNumberInKey;
		private String projectKey;
		private boolean prependParentProjectKey;
		private boolean disableInprogressNotification;

        public DescriptorImpl() {
            this(true);
        }

        protected DescriptorImpl(boolean load) {
            if (load) load();
        }

        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Item project) {

            if (project != null && project.hasPermission(Item.CONFIGURE)) {
                return new StandardListBoxModel()
                        .withEmptySelection()
                        .withMatching(
                                new StashCredentialMatcher(),
                                CredentialsProvider.lookupCredentials(
                                        StandardCredentials.class,
                                        project,
                                        ACL.SYSTEM,
                                        new ArrayList<DomainRequirement>()));
                
            } else if (Jenkins.getInstance().hasPermission(Item.CONFIGURE)) {
                return new StandardListBoxModel()
                        .withEmptySelection()
                        .withMatching(
                                new StashCredentialMatcher(),
                                CredentialsProvider.lookupCredentials(
                                        StandardCredentials.class,
                                        Jenkins.getInstance(),
                                        ACL.SYSTEM,
                                        new ArrayList<DomainRequirement>()));
            }

            return new StandardListBoxModel();
        }

        public String getStashRootUrl() {
        	if ((stashRootUrl == null) || (stashRootUrl.trim().equals(""))) {
        		return null;
        	} else {
	            return stashRootUrl;
        	}
        }

		public boolean isDisableInprogressNotification() {
			return disableInprogressNotification;
		}

		public String getCredentialsId() {
			return credentialsId;
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

		public FormValidation doCheckCredentialsId(@QueryParameter String value, @AncestorInPath Item project)
				throws IOException, ServletException {

			if (project != null && StringUtils.isBlank(value) && StringUtils.isBlank(credentialsId)) {
				return FormValidation.error("Please specify the credentials to use");
			} else {
				return FormValidation.ok();
			}
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
            stashRootUrl = formData.getString("stashRootUrl");
            ignoreUnverifiedSsl = formData.getBoolean("ignoreUnverifiedSsl");
            includeBuildNumberInKey = formData.getBoolean("includeBuildNumberInKey");

            if (formData.has("credentialsId") && StringUtils.isNotBlank(formData.getString("credentialsId"))) {
                credentialsId = formData.getString("credentialsId");
            }
            if (formData.has("projectKey")) {
                projectKey = formData.getString("projectKey");
            }
            prependParentProjectKey = formData.getBoolean("prependParentProjectKey");

			disableInprogressNotification = formData.getBoolean("disableInprogressNotification");

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
	 * @param listener		the build listener for logging
	 * @param state			the state of the build as defined by the Stash API.
	 */
	protected NotificationResult notifyStash(
			final PrintStream logger,
			final AbstractBuild<?, ?> build,
			final String commitSha1,
			final BuildListener listener,
			final StashBuildState state) throws Exception {
		HttpEntity stashBuildNotificationEntity
			= newStashBuildNotificationEntity(build, state, listener);
		HttpPost req = createRequest(stashBuildNotificationEntity, build.getProject(), commitSha1);
		HttpClient client = getHttpClient(logger,build);
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
     * A helper method to obtain the configured credentials.
     *
     * @param clazz The type of {@link com.cloudbees.plugins.credentials.Credentials} to return.
     * @param project The hierarchical project context within which the credentials are searched for.
     * @return The first credentials of the given type that are found withing the project hierarchy, or null otherwise.
     */
    private <T extends Credentials> T getCredentials(final Class<T> clazz, final Item project) {

        T credentials = null;

		if (clazz == CertificateCredentials.class) {
			return null;
		}

		String credentialsId = getCredentialsId();
        if (StringUtils.isNotBlank(credentialsId) && clazz != null && project != null) {
            credentials = CredentialsMatchers.firstOrNull(
                    lookupCredentials(clazz, project, ACL.SYSTEM, new ArrayList<DomainRequirement>()),
                    CredentialsMatchers.withId(credentialsId));
        }
        
        if (credentials == null) {
            DescriptorImpl descriptor = getDescriptor();
            if (StringUtils.isBlank(credentialsId) && descriptor != null) {
                credentialsId = descriptor.getCredentialsId();
            }
            if (StringUtils.isNotBlank(credentialsId) && clazz != null && project != null) {
                credentials =  CredentialsMatchers.firstOrNull(
                        lookupCredentials(clazz, Jenkins.getInstance(), ACL.SYSTEM, new ArrayList<DomainRequirement>()),
                        CredentialsMatchers.withId(credentialsId));
            }
        }

        return credentials;
    }

	/**
	 * Returns all credentials which are available to the specified {@link Authentication}
	 * for use by the specified {@link Item}.
	 *
	 * @param type               the type of credentials to get.
	 * @param authentication     the authentication.
	 * @param item               the item.
	 * @param domainRequirements the credential domains to match.
	 * @param <C>                the credentials type.
	 * @return the list of credentials.
	 */
	protected  <C extends Credentials> List<C> lookupCredentials(Class<C> type, Item item, Authentication authentication, ArrayList<DomainRequirement> domainRequirements) {
		return CredentialsProvider.lookupCredentials(type, item, authentication, domainRequirements);
	}

        /**
	 * Returns all credentials which are available to the specified {@link Authentication}
	 * for use by the specified {@link Item}.
	 *
	 * @param type               the type of credentials to get.
	 * @param authentication     the authentication.
	 * @param itemGroup          the item group.
	 * @param domainRequirements the credential domains to match.
	 * @param <C>                the credentials type.
	 * @return the list of credentials.
	 */
	protected  <C extends Credentials> List<C> lookupCredentials(Class<C> type, ItemGroup<?> itemGroup, Authentication authentication, ArrayList<DomainRequirement> domainRequirements) {
		return CredentialsProvider.lookupCredentials(type, itemGroup, authentication, domainRequirements);
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
    protected HttpPost createRequest(
			final HttpEntity stashBuildNotificationEntity,
            final Item project,
			final String commitSha1) {

		String url = stashServerBaseUrl;
        DescriptorImpl descriptor = getDescriptor();

        if ("".equals(url) || url == null)
            url = descriptor.getStashRootUrl();

		HttpPost req = new HttpPost(
				url
				+ "/rest/build-status/1.0/commits/"
				+ commitSha1);

		// If we have a credential defined then we need to determine if it
		// is a basic auth

        UsernamePasswordCredentials usernamePasswordCredentials =
                getCredentials(UsernamePasswordCredentials.class, project);

        if (usernamePasswordCredentials != null) {
            req.addHeader(BasicScheme.authenticate(
                    new org.apache.http.auth.UsernamePasswordCredentials(
                            usernamePasswordCredentials.getUsername(),
                            usernamePasswordCredentials.getPassword().getPlainText()),
                    "UTF-8",
                    false));
        }

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
			final StashBuildState state,
            BuildListener listener) throws UnsupportedEncodingException {

		JSONObject json = new JSONObject();

        json.put("state", state.name());

        json.put("key", abbreviate(getBuildKey(build, listener), MAX_FIELD_LENGTH));

        // This is to replace the odd character Jenkins injects to separate 
        // nested jobs, especially when using the Cloudbees Folders plugin. 
        // These characters cause Stash to throw up.
        String fullName = StringEscapeUtils.
                escapeJavaScript(build.getFullDisplayName()).
                replaceAll("\\\\u00BB", "\\/");
        json.put("name", abbreviate(fullName, MAX_FIELD_LENGTH));

		json.put("description", abbreviate(getBuildDescription(build, state), MAX_FIELD_LENGTH));
		json.put("url", abbreviate(getRootUrl().concat(build.getUrl()), MAX_URL_FIELD_LENGTH));

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
		if (includeBuildNumberInKey
				|| getDescriptor().isIncludeBuildNumberInKey()) {
			key.append('-').append(build.getNumber());
		}
		key.append('-').append(getRootUrl());

		return key.toString();
	}

	/**
	 * Returns the build key used in the Stash notification. Includes the
	 * build number depending on the user setting.
	 *
	 * @param 	build	the build to notify Stash of
	 * @return	the build key for the Stash notification
	 */
	protected String getBuildKey(final AbstractBuild<?, ?> build,
							   BuildListener listener) {

		StringBuilder key = new StringBuilder();

		if (prependParentProjectKey || getDescriptor().isPrependParentProjectKey()){
			if (null != build.getParent().getParent()) {
				key.append(build.getParent().getParent().getFullName()).append('-');
			}
		}

		String overriddenKey = (projectKey != null && projectKey.trim().length() > 0) ? projectKey : getDescriptor().getProjectKey();

		if (overriddenKey != null && overriddenKey.trim().length() > 0) {
			PrintStream logger = listener.getLogger();
			try {
				key.append(TokenMacro.expandAll(build, listener, projectKey));
			} catch (IOException e) {
				logger.println("Cannot expand build key from parameter. Processing with default build key");
				e.printStackTrace(logger);
				key.append(getDefaultBuildKey(build));
			} catch (InterruptedException e) {
				logger.println("Cannot expand build key from parameter. Processing with default build key");
				e.printStackTrace(logger);
				key.append(getDefaultBuildKey(build));
			} catch (MacroEvaluationException e) {
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
	protected String getBuildDescription(
			final AbstractBuild<?, ?> build,
			final StashBuildState state) {

		if (build.getDescription() != null
				&& build.getDescription().trim().length() > 0) {

			return build.getDescription();
		} else {
			switch (state) {
			case INPROGRESS:
	            return "building on Jenkins @ "
					+ getRootUrl();
			default:
	            return "built by Jenkins @ "
	            	+ getRootUrl();
			}
		}
	}
}
