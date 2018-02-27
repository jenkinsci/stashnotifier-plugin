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
import hudson.FilePath;
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
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.*;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
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
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.displayurlapi.DisplayURLProvider;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;
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
public class StashNotifier extends Notifier implements SimpleBuildStep {

    public static final int MAX_FIELD_LENGTH = 255;
    public static final int MAX_URL_FIELD_LENGTH = 450;

    // attributes --------------------------------------------------------------

    /**
     * base url of Stash server, e. g. <tt>http://localhost:7990</tt>.
     */
    private final String stashServerBaseUrl;

    /**
     * The id of the credentials to use.
     */
    private String credentialsId;

    /**
     * if true, ignore exception thrown in case of an unverified SSL peer.
     */
    private final boolean ignoreUnverifiedSSLPeer;

    /**
     * specify the commit from config
     */
    private final String commitSha1;

    /**
     * if true, the build number is included in the Stash notification.
     */
    private final boolean includeBuildNumberInKey;

    /**
     * specify project key manually
     */
    private final String projectKey;

    /**
     * append parent project key to key formation
     */
    private final boolean prependParentProjectKey;

    /**
     * whether to send INPROGRESS notification at the build start
     */
    private final boolean disableInprogressNotification;

    /**
     * whether to consider UNSTABLE builds as failures or success
     */
    private final boolean considerUnstableAsSuccess;

    /**
     * whether to bypass all state deduction logic and use value provided in customBuildState
     */
    private final boolean useCustomBuildState;

    /**
     * build state to send. used only if useCustomBuildState is true
     */
    private final String customBuildState;

    private JenkinsLocationConfiguration globalConfig = new JenkinsLocationConfiguration();

// public members ----------------------------------------------------------

    @Override
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
            boolean disableInprogressNotification,
            boolean considerUnstableAsSuccess,
            boolean useCustomBuildState,
            String customBuildState
    ) {


        this.stashServerBaseUrl = stashServerBaseUrl != null && stashServerBaseUrl.endsWith("/")
                ? stashServerBaseUrl.substring(0, stashServerBaseUrl.length() - 1)
                : stashServerBaseUrl;
        this.credentialsId = credentialsId;
        this.ignoreUnverifiedSSLPeer = ignoreUnverifiedSSLPeer;
        this.commitSha1 = commitSha1;
        this.includeBuildNumberInKey = includeBuildNumberInKey;
        this.projectKey = projectKey;
        this.prependParentProjectKey = prependParentProjectKey;
        this.disableInprogressNotification = disableInprogressNotification;
        this.considerUnstableAsSuccess = considerUnstableAsSuccess;
        this.useCustomBuildState = useCustomBuildState;
        this.customBuildState = customBuildState;
    }

    public boolean isDisableInprogressNotification() {
        return disableInprogressNotification;
    }

    public boolean isConsiderUnstableAsSuccess() {
        return considerUnstableAsSuccess;
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
        return disableInprogressNotification || processJenkinsEvent(build, null, listener, StashBuildState.INPROGRESS);
    }

    @Override
    public boolean perform(
            AbstractBuild<?, ?> build,
            Launcher launcher,
            BuildListener listener) {
        return perform(build, null, listener, disableInprogressNotification);
    }

    @Override
    public void perform(@Nonnull Run<?, ?> run,
                        @Nonnull FilePath workspace,
                        @Nonnull Launcher launcher,
                        @Nonnull TaskListener listener) throws InterruptedException, IOException {
        if (!perform(run, workspace, listener, false)) {
            run.setResult(Result.FAILURE);
        }
    }

    private boolean perform(Run<?, ?> run,
                            FilePath workspace,
                            TaskListener listener,
                            boolean disableInProgress) {
        StashBuildState state;
        PrintStream logger = listener.getLogger();

        if (useCustomBuildState) {
            try {
                state = StashBuildState.valueOf(customBuildState);
            } catch (IllegalArgumentException e) {
                state = StashBuildState.FAILED;
                logger.println("invalid build state: " + customBuildState);
            }
        } else {
            Result buildResult = run.getResult();
            if (buildResult == null && disableInProgress) {
                return true;
            } else if (buildResult == null) {
                state = StashBuildState.INPROGRESS;
            } else if (buildResult == Result.SUCCESS) {
                state = StashBuildState.SUCCESSFUL;
            } else if (buildResult == Result.UNSTABLE && considerUnstableAsSuccess) {
                logger.println("UNSTABLE reported to stash as SUCCESSFUL");
                state = StashBuildState.SUCCESSFUL;
            } else if (buildResult == Result.ABORTED && disableInProgress) {
                logger.println("ABORTED");
                return true;
            } else if (buildResult.equals(Result.NOT_BUILT)) {
                logger.println("NOT BUILT");
                return true;
            } else {
                state = StashBuildState.FAILED;
            }
        }

        return processJenkinsEvent(run, null, listener, state);
    }

    /**
     * Provide a fallback for getting the instance's root URL
     *
     * @return Root URL contained in the global config
     */
    private String getRootUrl() {
        Jenkins instance = Jenkins.getInstance();

        if (null == instance) {
            return globalConfig.getUrl();
        }

        return (instance.getRootUrl() != null) ? instance.getRootUrl() : globalConfig.getUrl();
    }

    /**
     * Processes the Jenkins events triggered before and after the run and
     * initiates the Stash notification.
     *
     * @param run       the run to notify Stash of
     * @param workspace the workspace of a non-AbstractBuild build
     * @param listener  the Jenkins build listener
     * @param state     the state of the build (in progress, success, failed)
     * @return always true in order not to abort the Job in case of
     * notification failures
     */
    private boolean processJenkinsEvent(
            final Run<?, ?> run,
            final FilePath workspace,
            final TaskListener listener,
            final StashBuildState state) {

        PrintStream logger = listener.getLogger();

        // exit if Jenkins root URL is not configured. Stash run API
        // requires valid link to run in CI system.
        if (getRootUrl() == null) {
            logger.println(
                    "Cannot notify Stash! (Jenkins Root URL not configured)");
            return true;
        }

        Collection<String> commitSha1s = lookupCommitSha1s(run, workspace, listener);
        for (String commitSha1 : commitSha1s) {
            try {
                NotificationResult result
                        = notifyStash(logger, run, commitSha1, listener, state);
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
            @SuppressWarnings("rawtypes") Run run,
            FilePath workspace,
            TaskListener listener) {

        if (commitSha1 != null && commitSha1.trim().length() > 0) {
            PrintStream logger = listener.getLogger();

            try {
                if (run instanceof AbstractBuild) {
                    return Arrays.asList(TokenMacro.expandAll((AbstractBuild) run, listener, commitSha1));
                } else {
                    return Arrays.asList(TokenMacro.expandAll(run, workspace, listener, commitSha1));
                }
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
        for (BuildData buildData : run.getActions(BuildData.class)) {
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

            // This might be different than the lastBuiltSha1 if using "Merge before run"
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
     * @param logger      the logger to log messages to
     * @param run
     * @param stashServer
     * @return the HttpClient
     */
    protected HttpClient getHttpClient(PrintStream logger, Run<?, ?> run, String stashServer) throws Exception {
        DescriptorImpl globalSettings = getDescriptor();

        CertificateCredentials certificateCredentials = getCredentials(CertificateCredentials.class, run.getParent());

        URL url = new URL(stashServer);
        HttpClientBuilder builder = HttpClientBuilder.create();
        RequestConfig.Builder requestBuilder = RequestConfig.custom();
        requestBuilder = requestBuilder.setSocketTimeout(60000);
        builder.setDefaultRequestConfig(requestBuilder.build());

        boolean ignoreUnverifiedSSL = ignoreUnverifiedSSLPeer || globalSettings.isIgnoreUnverifiedSsl();
        if (url.getProtocol().equals("https") && ignoreUnverifiedSSL) {
            // add unsafe trust manager to avoid thrown
            // SSLPeerUnverifiedException
            try {
                final SSLContext sslContext = buildSslContext(ignoreUnverifiedSSL, certificateCredentials);
                SSLConnectionSocketFactory sslConnSocketFactory = new SSLConnectionSocketFactory(
                        sslContext,
                        new String[]{"TLSv1", "TLSv1.1", "TLSv1.2"},
                        null,
                        SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER
                );
                builder.setSSLSocketFactory(sslConnSocketFactory);

                Registry<ConnectionSocketFactory> registry
                        = RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("https", sslConnSocketFactory)
                        .register("http", PlainConnectionSocketFactory.INSTANCE)
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
        configureProxy(builder, url);

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
            customContext = customContext.loadKeyMaterial(((CertificateCredentials) credentials).getKeyStore(), ((CertificateCredentials) credentials).getPassword().getPlainText().toCharArray());
        }
        if (ignoreUnverifiedSSL) {
            TrustStrategy easyStrategy = new TrustStrategy() {
                @Override
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

    private void configureProxy(HttpClientBuilder builder, URL url) {
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            return;
        }

        ProxyConfiguration proxyConfig = jenkins.proxy;
        if (proxyConfig == null) {
            return;
        }

        Proxy proxy = proxyConfig.createProxy(url.getHost());
        if (proxy == null || proxy.type() != Proxy.Type.HTTP) {
            return;
        }

        SocketAddress addr = proxy.address();
        if (addr == null || !(addr instanceof InetSocketAddress)) {
            return;
        }

        InetSocketAddress proxyAddr = (InetSocketAddress) addr;
        HttpHost proxyHost = new HttpHost(proxyAddr.getAddress().getHostAddress(), proxyAddr.getPort());
        builder.setProxy(proxyHost);

        String proxyUser = proxyConfig.getUserName();
        if (proxyUser != null) {
            String proxyPass = proxyConfig.getPassword();
            BasicCredentialsProvider cred = new BasicCredentialsProvider();
            cred.setCredentials(new AuthScope(proxyHost),
                    new org.apache.http.auth.UsernamePasswordCredentials(proxyUser, proxyPass));
            builder.setDefaultCredentialsProvider(cred)
                    .setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
        }
    }

    @Override
    public DescriptorImpl getDescriptor() {
        // see Descriptor javadoc for more about what a descriptor is.
        return (DescriptorImpl) super.getDescriptor();
    }

    @Symbol({"notifyBitbucket", "notifyStash"})
    @Extension
    public static final class DescriptorImpl
            extends BuildStepDescriptor<Publisher> {

        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         * <p>
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
        private boolean considerUnstableAsSuccess;

        public DescriptorImpl() {
            this(true);
        }

        protected DescriptorImpl(boolean load) {
            if (load) load();
        }

        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Item project) {
            Jenkins jenkins = Jenkins.getInstance();

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
            } else if (jenkins != null && jenkins.hasPermission(Item.CONFIGURE)) {
                return new StandardListBoxModel()
                        .withEmptySelection()
                        .withMatching(
                                new StashCredentialMatcher(),
                                CredentialsProvider.lookupCredentials(
                                        StandardCredentials.class,
                                        jenkins,
                                        ACL.SYSTEM,
                                        new ArrayList<DomainRequirement>()));
            }

            return new StandardListBoxModel();
        }

        public String getStashRootUrl() {
            if ((stashRootUrl == null) || (stashRootUrl.trim().isEmpty())) {
                return null;
            } else {
                return stashRootUrl;
            }
        }

        public boolean isDisableInprogressNotification() {
            return disableInprogressNotification;
        }

        public boolean isConsiderUnstableAsSuccess() {
            return considerUnstableAsSuccess;
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
            if ((url != null) && (!url.trim().isEmpty())) {
                url = url.trim();
            } else {
                url = stashRootUrl != null ? stashRootUrl.trim() : null;
            }

            if ((url == null) || url.isEmpty()) {
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
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
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

            considerUnstableAsSuccess = formData.getBoolean("considerUnstableAsSuccess");

            save();
            return super.configure(req, formData);
        }
    }

    // non-public members ------------------------------------------------------

    /**
     * Notifies the configured Stash server by POSTing the run results
     * to the Stash run API.
     *
     * @param logger     the logger to use
     * @param run        the run to notify Stash of
     * @param commitSha1 the SHA1 of the run commit
     * @param listener   the run listener for logging
     * @param state      the state of the build as defined by the Stash API.
     */
    protected NotificationResult notifyStash(
            final PrintStream logger,
            final Run<?, ?> run,
            final String commitSha1,
            final TaskListener listener,
            final StashBuildState state) throws Exception {
        HttpEntity stashBuildNotificationEntity
                = newStashBuildNotificationEntity(run, state, listener);

        String stashURL = expandStashURL(run, listener);

        logger.println("Notifying Stash at \"" + stashURL + "\"");

        HttpPost req = createRequest(stashBuildNotificationEntity, run.getParent(), commitSha1, stashURL);
        HttpClient client = getHttpClient(logger, run, stashURL);
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
     * @param clazz   The type of {@link com.cloudbees.plugins.credentials.Credentials} to return.
     * @param project The hierarchical project context within which the credentials are searched for.
     * @return The first credentials of the given type that are found within the project hierarchy, or null otherwise.
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
                credentials = CredentialsMatchers.firstOrNull(
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
    protected <C extends Credentials> List<C> lookupCredentials(Class<C> type, Item item, Authentication authentication, ArrayList<DomainRequirement> domainRequirements) {
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
    protected <C extends Credentials> List<C> lookupCredentials(Class<C> type, ItemGroup<?> itemGroup, Authentication authentication, ArrayList<DomainRequirement> domainRequirements) {
        return CredentialsProvider.lookupCredentials(type, itemGroup, authentication, domainRequirements);
    }

    /**
     * Returns the HTTP POST request ready to be sent to the Stash build API for
     * the given run and change set.
     *
     * @param stashBuildNotificationEntity a entity containing the parameters
     *                                     for Stash
     * @param commitSha1                   the SHA1 of the commit that was built
     * @param url
     * @return the HTTP POST request to the Stash build API
     */
    protected HttpPost createRequest(
            final HttpEntity stashBuildNotificationEntity,
            final Item project,
            final String commitSha1,
            final String url) throws AuthenticationException {

        HttpPost req = new HttpPost(
                url
                        + "/rest/build-status/1.0/commits/"
                        + commitSha1);

        // If we have a credential defined then we need to determine if it
        // is a basic auth
        UsernamePasswordCredentials usernamePasswordCredentials
                = getCredentials(UsernamePasswordCredentials.class, project);

        if (usernamePasswordCredentials != null) {
            req.addHeader(new BasicScheme().authenticate(
                    new org.apache.http.auth.UsernamePasswordCredentials(
                            usernamePasswordCredentials.getUsername(),
                            usernamePasswordCredentials.getPassword().getPlainText()),
                    req,
                    null));
        }

        req.addHeader("Content-type", "application/json");
        req.setEntity(stashBuildNotificationEntity);

        return req;
    }

    private String expandStashURL(Run<?, ?> run, final TaskListener listener) {
        String url = stashServerBaseUrl;
        DescriptorImpl descriptor = getDescriptor();
        if (url == null || url.isEmpty()) {
            url = descriptor.getStashRootUrl();
        }

        try {
            if (!(run instanceof AbstractBuild<?, ?>)) {
                url = TokenMacro.expandAll(run, new FilePath(run.getRootDir()), listener, url);
            } else {
                url = TokenMacro.expandAll((AbstractBuild<?, ?>) run, listener, url);
            }

        } catch (IOException | InterruptedException | MacroEvaluationException ex) {
            PrintStream logger = listener.getLogger();
            logger.println("Unable to expand Stash Server URL");
            ex.printStackTrace(logger);
        }
        return url;
    }

    /**
     * Returns the HTTP POST entity body with the JSON representation of the
     * run result to be sent to the Stash build API.
     *
     * @param run the run to notify Stash of
     * @return HTTP entity body for POST to Stash build API
     */
    private HttpEntity newStashBuildNotificationEntity(
            final Run<?, ?> run,
            final StashBuildState state,
            TaskListener listener) throws UnsupportedEncodingException {

        JSONObject json = new JSONObject();

        json.put("state", state.name());

        json.put("key", abbreviate(getBuildKey(run, listener), MAX_FIELD_LENGTH));

        json.put("name", abbreviate(run.getFullDisplayName(), MAX_FIELD_LENGTH));

        json.put("description", abbreviate(getBuildDescription(run, state), MAX_FIELD_LENGTH));
        json.put("url", abbreviate(DisplayURLProvider.get().getRunURL(run), MAX_URL_FIELD_LENGTH));

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
     * @param run the run to notify Stash of
     * @return default build key
     */
    private String getDefaultBuildKey(final Run<?, ?> run) {
        StringBuilder key = new StringBuilder();

        key.append(run.getParent().getName());
        if (includeBuildNumberInKey
                || getDescriptor().isIncludeBuildNumberInKey()) {
            key.append('-').append(run.getNumber());
        }
        key.append('-').append(getRootUrl());

        return key.toString();
    }

    /**
     * Returns the run key used in the Stash notification. Includes the
     * run number depending on the user setting.
     *
     * @param run the run to notify Stash of
     * @return the run key for the Stash notification
     */
    protected String getBuildKey(final Run<?, ?> run,
                                 TaskListener listener) {

        StringBuilder key = new StringBuilder();

        if (prependParentProjectKey || getDescriptor().isPrependParentProjectKey()) {
            if (null != run.getParent().getParent()) {
                key.append(run.getParent().getParent().getFullName()).append('-');
            }
        }

        String overriddenKey = (projectKey != null && projectKey.trim().length() > 0) ? projectKey : getDescriptor().getProjectKey();
        if (overriddenKey != null && overriddenKey.trim().length() > 0) {
            PrintStream logger = listener.getLogger();
            try {
                if (!(run instanceof AbstractBuild<?, ?>)) {
                    key.append(TokenMacro.expandAll(run, new FilePath(run.getRootDir()), listener, projectKey));
                } else {
                    key.append(TokenMacro.expandAll((AbstractBuild<?, ?>) run, listener, projectKey));
                }
            } catch (IOException ioe) {
                logger.println("Cannot expand build key from parameter. Processing with default build key");
                ioe.printStackTrace(logger);
                key.append(getDefaultBuildKey(run));
            } catch (InterruptedException ie) {
                logger.println("Cannot expand build key from parameter. Processing with default build key");
                ie.printStackTrace(logger);
                key.append(getDefaultBuildKey(run));
            } catch (MacroEvaluationException mee) {
                logger.println("Cannot expand build key from parameter. Processing with default build key");
                mee.printStackTrace(logger);
                key.append(getDefaultBuildKey(run));
            }
        } else {
            key.append(getDefaultBuildKey(run));
        }

        return StringEscapeUtils.escapeJavaScript(key.toString());
    }

    /**
     * Returns the description of the run used for the Stash notification.
     * Uses the run description provided by the Jenkins job, if available.
     *
     * @param run   the run to be described
     * @param state the state of the run
     * @return the description of the run
     */
    protected String getBuildDescription(
            final Run<?, ?> run,
            final StashBuildState state) {

        if (run.getDescription() != null
                && run.getDescription().trim().length() > 0) {

            return run.getDescription();
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
