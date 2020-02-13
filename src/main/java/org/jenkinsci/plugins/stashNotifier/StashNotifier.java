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
import com.cloudbees.plugins.credentials.common.CertificateCredentials;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
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
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.*;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.displayurlapi.DisplayURLProvider;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.*;

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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

/**
 * Notifies a configured Atlassian Bitbucket server instance of build results
 * through the Bitbucket build API.
 * <p>
 * Only basic authentication is supported at the moment.
 */
public class StashNotifier extends Notifier implements SimpleBuildStep {

    public static final int MAX_FIELD_LENGTH = 255;
    public static final int MAX_URL_FIELD_LENGTH = 450;

    // attributes --------------------------------------------------------------

    /**
     * base url of Bitbucket server, e. g. <tt>http://localhost:7990</tt>.
     */
    private String stashServerBaseUrl;

    /**
     * The id of the credentials to use.
     */
    private String credentialsId;

    /**
     * if true, ignore exception thrown in case of an unverified SSL peer.
     */
    private boolean ignoreUnverifiedSSLPeer;

    /**
     * specify the commit from config
     */
    private String commitSha1;

    /**
     * specify a specific build state to be pushed.
     * If null, the current build result will be used.
     */
    private StashBuildState buildStatus;

    /**
     * specify a build name to be included in the Bitbucket notification.
     * If null, the usual full project name will be used.
     */
    private String buildName;

    /**
     * if true, the build number is included in the Bitbucket notification.
     */
    private boolean includeBuildNumberInKey;

    /**
     * specify project key manually
     */
    private String projectKey;

    /**
     * append parent project key to key formation
     */
    private boolean prependParentProjectKey;

    /**
     * whether to send INPROGRESS notification at the build start
     */
    private boolean disableInprogressNotification;

    /**
     * whether to consider UNSTABLE builds as failures or success
     */
    private boolean considerUnstableAsSuccess;

    private JenkinsLocationConfiguration globalConfig;

// public members ----------------------------------------------------------

    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }

    StashNotifier(
            String stashServerBaseUrl,
            String credentialsId,
            boolean ignoreUnverifiedSSLPeer,
            String commitSha1,
            String buildStatus,
            String buildName,
            boolean includeBuildNumberInKey,
            String projectKey,
            boolean prependParentProjectKey,
            boolean disableInprogressNotification,
            boolean considerUnstableAsSuccess,
            JenkinsLocationConfiguration globalConfig
    ) {
        this.globalConfig = globalConfig;
        setStashServerBaseUrl(stashServerBaseUrl);
        setCredentialsId(credentialsId);
        setIgnoreUnverifiedSSLPeer(ignoreUnverifiedSSLPeer);
        setCommitSha1(commitSha1);
        setBuildStatus(buildStatus);
        setBuildName(buildName);
        setIncludeBuildNumberInKey(includeBuildNumberInKey);
        setProjectKey(projectKey);
        setPrependParentProjectKey(prependParentProjectKey);
        setDisableInprogressNotification(disableInprogressNotification);
        setConsiderUnstableAsSuccess(considerUnstableAsSuccess);
    }

    StashNotifier(
            JenkinsLocationConfiguration globalConfig
    ) {
        this.globalConfig = globalConfig;
    }

    @DataBoundConstructor
    public StashNotifier() {
        this(
                JenkinsLocationConfiguration.get()
        );
    }

    public String getStashServerBaseUrl() {
        return stashServerBaseUrl;
    }

    @DataBoundSetter
    public void setStashServerBaseUrl(String stashServerBaseUrl) {
        this.stashServerBaseUrl = StringUtils.stripEnd(stashServerBaseUrl, "/");
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    @DataBoundSetter
    public void setCredentialsId(String credentialsId) {
        this.credentialsId = credentialsId;
    }

    public boolean isIgnoreUnverifiedSSLPeer() {
        return ignoreUnverifiedSSLPeer;
    }

    @DataBoundSetter
    public void setIgnoreUnverifiedSSLPeer(boolean ignoreUnverifiedSSLPeer) {
        this.ignoreUnverifiedSSLPeer = ignoreUnverifiedSSLPeer;
    }

    public String getCommitSha1() {
        return commitSha1;
    }

    @DataBoundSetter
    public void setCommitSha1(String commitSha1) {
        this.commitSha1 = commitSha1;
    }

    public StashBuildState getBuildStatus() {
        return buildStatus;
    }

    public void setBuildStatus(StashBuildState buildStatus) {
        this.buildStatus = buildStatus;
    }

    @DataBoundSetter
    public void setBuildStatus(String buildStatus) {
        try {
            this.buildStatus = StashBuildState.valueOf(buildStatus);
        } catch (Exception e) {
            // ignore unknown or null values
        }
    }

    public String getBuildName() {
        return buildName;
    }

    @DataBoundSetter
    public void setBuildName(String buildName) {
        this.buildName = buildName;
    }

    public boolean isIncludeBuildNumberInKey() {
        return includeBuildNumberInKey;
    }

    @DataBoundSetter
    public void setIncludeBuildNumberInKey(boolean includeBuildNumberInKey) {
        this.includeBuildNumberInKey = includeBuildNumberInKey;
    }

    public String getProjectKey() {
        return projectKey;
    }

    @DataBoundSetter
    public void setProjectKey(String projectKey) {
        this.projectKey = projectKey;
    }

    public boolean isPrependParentProjectKey() {
        return prependParentProjectKey;
    }

    @DataBoundSetter
    public void setPrependParentProjectKey(boolean prependParentProjectKey) {
        this.prependParentProjectKey = prependParentProjectKey;
    }

    public boolean isDisableInprogressNotification() {
        return disableInprogressNotification;
    }

    @DataBoundSetter
    public void setDisableInprogressNotification(boolean disableInprogressNotification) {
        this.disableInprogressNotification = disableInprogressNotification;
    }

    public boolean isConsiderUnstableAsSuccess() {
        return considerUnstableAsSuccess;
    }

    @DataBoundSetter
    public void setConsiderUnstableAsSuccess(boolean considerUnstableAsSuccess) {
        this.considerUnstableAsSuccess = considerUnstableAsSuccess;
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

        Result buildResult = run.getResult();
        if (buildResult == null && disableInProgress) {
            return true;
        } else if (buildResult == null) {
            state = StashBuildState.INPROGRESS;
        } else if (buildResult == Result.SUCCESS) {
            state = StashBuildState.SUCCESSFUL;
        } else if (buildResult == Result.UNSTABLE && considerUnstableAsSuccess) {
            logger.println("UNSTABLE reported to Bitbucket as SUCCESSFUL");
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

        return processJenkinsEvent(run, null, listener, state);
    }

    /**
     * Provide a fallback for getting the instance's root URL
     *
     * @return Root URL contained in the global config
     */
    private String getRootUrl() {
        Jenkins instance = Jenkins.getInstance();

        return (instance.getRootUrl() != null) ? instance.getRootUrl() : globalConfig.getUrl();
    }

    /**
     * Processes the Jenkins events triggered before and after the run and
     * initiates the Bitbucket notification.
     *
     * @param run       the run to notify Bitbucket of
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

        // Exit if Jenkins root URL is not configured. Bitbucket run API
        // requires valid link to run in CI system.
        if (getRootUrl() == null) {
            logger.println("Cannot notify Bitbucket! (Jenkins Root URL not configured)");
            return true;
        }

        Collection<String> commitSha1s = lookupCommitSha1s(run, workspace, listener);
        for (String commitSha1 : commitSha1s) {
            try {
                NotificationResult result
                        = notifyStash(logger, run, commitSha1, listener, state);
                if (result.indicatesSuccess) {
                    logger.println("Notified Bitbucket for commit with id " + commitSha1);
                } else {
                    logger.println(
                            "Failed to notify Bitbucket for commit "
                                    + commitSha1
                                    + " (" + result.message + ")");
                }
            } catch (SSLPeerUnverifiedException e) {
                logger.println("SSLPeerUnverifiedException caught while "
                        + "notifying Bitbucket. Make sure your SSL certificate on "
                        + "your Bitbucket server is valid or check the "
                        + " 'Ignore unverifiable SSL certificate' checkbox in the "
                        + "plugin configuration of this job.");
            } catch (Exception e) {
                logger.println("Caught exception while notifying Bitbucket with id "
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
                    return Collections.singletonList(TokenMacro.expandAll((AbstractBuild) run, listener, commitSha1));
                } else {
                    return Collections.singletonList(TokenMacro.expandAll(run, workspace, listener, commitSha1));
                }
            } catch (IOException | InterruptedException | MacroEvaluationException e) {
                logger.println("Unable to expand commit SHA value");
                e.printStackTrace(logger);
                return Collections.emptyList();
            }
        }

        // Use a set to remove duplicates
        Collection<String> sha1s = new HashSet<>();
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
     */
    protected CloseableHttpClient getHttpClient(PrintStream logger, Run<?, ?> run, String stashServer) throws Exception {
        DescriptorImpl globalSettings = getDescriptor();

        CertificateCredentials certificateCredentials = getCredentials(CertificateCredentials.class, run.getParent());

        final int timeoutInMilliseconds = 60_000;

        RequestConfig.Builder requestBuilder = RequestConfig.custom()
                                            .setSocketTimeout(timeoutInMilliseconds)
                                            .setConnectTimeout(timeoutInMilliseconds)
                                            .setConnectionRequestTimeout(timeoutInMilliseconds);

        HttpClientBuilder clientBuilder = HttpClients.custom();
        clientBuilder.setDefaultRequestConfig(requestBuilder.build());

        URL url = new URL(stashServer);
        boolean ignoreUnverifiedSSL = ignoreUnverifiedSSLPeer || globalSettings.isIgnoreUnverifiedSsl();

        if (url.getProtocol().equals("https") && ignoreUnverifiedSSL) {
            // add unsafe trust manager to avoid thrown SSLPeerUnverifiedException
            try {
                SSLContext sslContext = buildSslContext(ignoreUnverifiedSSL, certificateCredentials);
                SSLConnectionSocketFactory sslConnSocketFactory = new SSLConnectionSocketFactory(
                        sslContext,
                        new String[]{"TLSv1", "TLSv1.1", "TLSv1.2"},
                        null,
                        NoopHostnameVerifier.INSTANCE
                );
                clientBuilder.setSSLSocketFactory(sslConnSocketFactory);

                Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("https", sslConnSocketFactory)
                        .register("http", PlainConnectionSocketFactory.INSTANCE)
                        .build();

                HttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(registry);
                clientBuilder.setConnectionManager(connectionManager);
            } catch (NoSuchAlgorithmException nsae) {
                logger.println("Couldn't establish SSL context:");
                nsae.printStackTrace(logger);
            } catch (KeyManagementException | KeyStoreException e) {
                logger.println("Couldn't initialize SSL context:");
                e.printStackTrace(logger);
            }
        }

        // Configure the proxy, if needed
        // Using the Jenkins methods handles the noProxyHost settings
        configureProxy(clientBuilder, url);

        return clientBuilder.build();
    }

    /**
     * Helper in place to allow us to define out HttpClient SSL context
     */
    private SSLContext buildSslContext(boolean ignoreUnverifiedSSL, Credentials credentials) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        SSLContextBuilder contextBuilder = SSLContexts.custom();
        contextBuilder.setProtocol("TLS");
        if (credentials instanceof CertificateCredentials) {
            contextBuilder.loadKeyMaterial(
                    ((CertificateCredentials) credentials).getKeyStore(),
                    ((CertificateCredentials) credentials).getPassword().getPlainText().toCharArray());
        }
        if (ignoreUnverifiedSSL) {
            contextBuilder.loadTrustMaterial(null, TrustAllStrategy.INSTANCE);
        }
        return contextBuilder.build();
    }

    private void configureProxy(HttpClientBuilder builder, URL url) {
        Jenkins jenkins = Jenkins.getInstance();
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

        private boolean considerUnstableAsSuccess;
        private String credentialsId;
        private boolean disableInprogressNotification;
        private boolean ignoreUnverifiedSsl;
        private boolean includeBuildNumberInKey;
        private boolean prependParentProjectKey;
        private String stashRootUrl;

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
                                        new ArrayList<>()));
            } else if (jenkins != null && jenkins.hasPermission(Item.CONFIGURE)) {
                return new StandardListBoxModel()
                        .withEmptySelection()
                        .withMatching(
                                new StashCredentialMatcher(),
                                CredentialsProvider.lookupCredentials(
                                        StandardCredentials.class,
                                        jenkins,
                                        ACL.SYSTEM,
                                        new ArrayList<>()));
            }

            return new StandardListBoxModel();
        }

        public boolean isConsiderUnstableAsSuccess() {
            return considerUnstableAsSuccess;
        }

        @DataBoundSetter
        public void setConsiderUnstableAsSuccess(boolean considerUnstableAsSuccess) {
            this.considerUnstableAsSuccess = considerUnstableAsSuccess;
        }

        public String getCredentialsId() {
            return credentialsId;
        }

        @DataBoundSetter
        public void setCredentialsId(String credentialsId) {
            this.credentialsId = StringUtils.trimToNull(credentialsId);
        }

        public boolean isDisableInprogressNotification() {
            return disableInprogressNotification;
        }

        @DataBoundSetter
        public void setDisableInprogressNotification(boolean disableInprogressNotification) {
            this.disableInprogressNotification = disableInprogressNotification;
        }

        public boolean isIgnoreUnverifiedSsl() {
            return ignoreUnverifiedSsl;
        }

        @DataBoundSetter
        public void setIgnoreUnverifiedSsl(boolean ignoreUnverifiedSsl) {
            this.ignoreUnverifiedSsl = ignoreUnverifiedSsl;
        }

        public boolean isIncludeBuildNumberInKey() {
            return includeBuildNumberInKey;
        }

        @DataBoundSetter
        public void setIncludeBuildNumberInKey(boolean includeBuildNumberInKey) {
            this.includeBuildNumberInKey = includeBuildNumberInKey;
        }

        public boolean isPrependParentProjectKey() {
            return prependParentProjectKey;
        }

        @DataBoundSetter
        public void setPrependParentProjectKey(boolean prependParentProjectKey) {
            this.prependParentProjectKey = prependParentProjectKey;
        }

        public String getStashRootUrl() {
            return stashRootUrl;
        }

        @DataBoundSetter
        public void setStashRootUrl(String stashRootUrl) {
            this.stashRootUrl = StringUtils.trimToNull(stashRootUrl);
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
            return "Notify Bitbucket Instance";
        }

        @Override
        public boolean configure(
                StaplerRequest req,
                JSONObject formData) throws FormException {

            this.considerUnstableAsSuccess = false;
            this.credentialsId = null;
            this.disableInprogressNotification = false;
            this.ignoreUnverifiedSsl = false;
            this.includeBuildNumberInKey = false;
            this.prependParentProjectKey = false;
            this.stashRootUrl = null;

            req.bindJSON(this, formData);

            save();

            return true;
        }
    }

    // non-public members ------------------------------------------------------

    /**
     * Notifies the configured Bitbucket server by POSTing the run results
     * to the Bitbucket run API.
     *
     * @param logger     the logger to use
     * @param run        the run to notify Bitbucket of
     * @param commitSha1 the SHA1 of the run commit
     * @param listener   the run listener for logging
     * @param state      the state of the build as defined by the Bitbucket API.
     */
    protected NotificationResult notifyStash(
            final PrintStream logger,
            final Run<?, ?> run,
            final String commitSha1,
            final TaskListener listener,
            final StashBuildState state) throws Exception {
        StashBuildState buildStatus = getPushedBuildStatus(state);
        HttpEntity stashBuildNotificationEntity = newStashBuildNotificationEntity(run, buildStatus, listener);

        String stashURL = expandStashURL(run, listener);

        logger.println("Notifying Bitbucket at \"" + stashURL + "\"");

        HttpPost req = createRequest(stashBuildNotificationEntity, run.getParent(), commitSha1, stashURL);
        try (CloseableHttpClient client = getHttpClient(logger, run, stashURL)) {
            HttpResponse res = client.execute(req);
            if (res.getStatusLine().getStatusCode() != 204) {
                return NotificationResult.newFailure(
                        EntityUtils.toString(res.getEntity()));
            } else {
                return NotificationResult.newSuccess();
            }
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
                    CredentialsProvider.lookupCredentials(clazz, project, ACL.SYSTEM, new ArrayList<>()),
                    CredentialsMatchers.withId(credentialsId));
        }

        if (credentials == null) {
            DescriptorImpl descriptor = getDescriptor();
            if (StringUtils.isBlank(credentialsId) && descriptor != null) {
                credentialsId = descriptor.getCredentialsId();
            }
            if (StringUtils.isNotBlank(credentialsId) && clazz != null && project != null) {
                credentials = CredentialsMatchers.firstOrNull(
                        CredentialsProvider.lookupCredentials(clazz, Jenkins.getInstance(), ACL.SYSTEM, new ArrayList<>()),
                        CredentialsMatchers.withId(credentialsId));
            }
        }

        return credentials;
    }

    /**
     * Returns the build state to be pushed. This will select the specifically overwritten build state
     * or the current build state else.
     *
     * @param currentBuildStatus the state of the current build
     * @return the selected build state
     */
    protected StashBuildState getPushedBuildStatus(StashBuildState currentBuildStatus) {
        if (buildStatus != null) {
            return buildStatus;
        } else {
            return currentBuildStatus;
        }
    }

    /**
     * Returns the HTTP POST request ready to be sent to the Bitbucket build API for
     * the given run and change set.
     *
     * @param stashBuildNotificationEntity a entity containing the parameters for Bitbucket
     * @param commitSha1                   the SHA1 of the commit that was built
     * @param url
     * @return the HTTP POST request to the Bitbucket build API
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

        req.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
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
            logger.println("Unable to expand Bitbucker server URL");
            ex.printStackTrace(logger);
        }
        return url;
    }

    /**
     * Returns the HTTP POST entity body with the JSON representation of the
     * run result to be sent to the Bitbucket build API.
     *
     * @param run the run to notify Bitbucket of
     * @return HTTP entity body for POST to Bitbucket build API
     */
    private HttpEntity newStashBuildNotificationEntity(
            final Run<?, ?> run,
            final StashBuildState state,
            TaskListener listener) throws UnsupportedEncodingException {

        JSONObject json = new JSONObject();

        json.put("state", state.name());

        json.put("key", abbreviate(getBuildKey(run, listener), MAX_FIELD_LENGTH));

        json.put("name", abbreviate(getBuildName(run), MAX_FIELD_LENGTH));

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
     * @param run the run to notify Bitbucket of
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

        if (buildName != null && buildName.trim().length() > 0) {
            key.append('-').append(buildName);
        }

        return key.toString();
    }

    /**
     * Returns the run key used in the Bitbucket notification. Includes the
     * run number depending on the user setting.
     *
     * @param run the run to notify Bitbucket of
     * @return the run key for the Bitbucket notification
     */
    protected String getBuildKey(final Run<?, ?> run,
                                 TaskListener listener) {

        StringBuilder key = new StringBuilder();

        if (prependParentProjectKey || getDescriptor().isPrependParentProjectKey()) {
            if (null != run.getParent().getParent()) {
                key.append(run.getParent().getParent().getFullName()).append('-');
            }
        }

        if (projectKey != null && projectKey.trim().length() > 0) {
            PrintStream logger = listener.getLogger();
            try {
                if (!(run instanceof AbstractBuild<?, ?>)) {
                    key.append(TokenMacro.expandAll(run, new FilePath(run.getRootDir()), listener, projectKey));
                } else {
                    key.append(TokenMacro.expandAll((AbstractBuild<?, ?>) run, listener, projectKey));
                }
            } catch (IOException | InterruptedException | MacroEvaluationException ioe) {
                logger.println("Cannot expand build key from parameter. Processing with default build key");
                ioe.printStackTrace(logger);
                key.append(getDefaultBuildKey(run));
            }
        } else {
            key.append(getDefaultBuildKey(run));
        }

        return StringEscapeUtils.escapeJavaScript(key.toString());
    }

    /**
     * Returns the build name to be pushed. This will select the specifically overwritten build name
     * or get the build name from the {@link Run}.
     *
     * @param run the run to notify Bitbucket of
     * @return the selected build state
     */
    protected String getBuildName(final Run<?, ?> run) {
        if (buildName != null && buildName.trim().length() > 0) {
            return buildName;
        } else {
            return run.getFullDisplayName();
        }
    }

    /**
     * Returns the description of the run used for the Bitbucket notification.
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
