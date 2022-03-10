package org.jenkinsci.plugins.stashNotifier;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.ProxyConfiguration;
import hudson.model.*;
import hudson.plugins.git.Revision;
import hudson.plugins.git.util.Build;
import hudson.plugins.git.util.BuildData;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.model.JenkinsLocationConfiguration;
import org.acegisecurity.Authentication;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.HttpHost;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthenticationStrategy;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jenkinsci.plugins.displayurlapi.DisplayURLProvider;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.mockito.MockedStatic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class StashNotifierTest {

    final static String sha1 = "1234567890123456789012345678901234567890";
    private static HttpClientBuilder httpClientBuilder;
    private static CloseableHttpClient client;
    private static Jenkins jenkins;
    private static final HttpNotifierSelector httpNotifierSelector = mock(HttpNotifierSelector.class);
    private static final HttpNotifier httpNotifier = mock(HttpNotifier.class);

    private static MockedStatic<Jenkins> mockedJenkins;
    private static MockedStatic<com.cloudbees.plugins.credentials.CredentialsProvider> mockedCredentialsProvider;
    private static MockedStatic<Secret> mockedSecret;
    private static MockedStatic<HttpClientBuilder> mockedHttpClientBuilder;

    private static StashNotifier buildStashNotifier(String stashBaseUrl) {
        return buildStashNotifier(stashBaseUrl, false, false);
    }

    private static StashNotifier buildStashNotifier(String stashBaseUrl,
                                            boolean disableInprogressNotification,
                                            boolean considerUnstableAsSuccess) {
        StashNotifier notifier = new StashNotifier(
                stashBaseUrl,
                "scot",
                true,
                null,
                null,
                null,
                true,
                "test-project",
                true,
                disableInprogressNotification,
                considerUnstableAsSuccess,
                mock(JenkinsLocationConfiguration.class)
        );
        notifier.setHttpNotifierSelector(httpNotifierSelector);
        return notifier;
    }

    private static StashNotifier sn;
    private static BuildListener buildListener;
    private static AbstractBuild<?, ?> build;
    private static Run<?, ?> run;
    private static FilePath workspace;

    @BeforeClass
    public static void setUp() throws Exception {
        mockedJenkins = mockStatic(Jenkins.class);
        mockedSecret = mockStatic(Secret.class);
        mockedHttpClientBuilder = mockStatic(HttpClientBuilder.class);
        mockedCredentialsProvider = mockStatic(
                com.cloudbees.plugins.credentials.CredentialsProvider.class);

        buildListener = mock(BuildListener.class);
        jenkins = mock(Jenkins.class);
        build = mock(AbstractBuild.class);
        run = mock(Run.class);
        AbstractProject project = mock(FreeStyleProject.class);
        File file = mock(File.class);
        when(file.getPath()).thenReturn("/tmp/fake/path");
        FilePath filePath = new FilePath(file);
        when(project.getSomeWorkspace()).thenReturn(filePath);
        workspace = project.getSomeWorkspace();
        EnvVars environment = mock(EnvVars.class);
        PrintStream logger = System.out;
        Secret secret = mock(Secret.class);
        httpClientBuilder = mock(HttpClientBuilder.class);
        client = mock(CloseableHttpClient.class);
        CloseableHttpResponse resp = mock(CloseableHttpResponse.class);
        HttpUriRequest req = mock(HttpUriRequest.class);
        StatusLine statusLine = mock(StatusLine.class);
        BuildData action = mock(BuildData.class);
        Revision revision = mock(Revision.class);
        Build lastBuild = mock(Build.class);
        List<BuildData> actions = Collections.singletonList(action);

        when(Jenkins.get()).thenReturn(jenkins);
        when(jenkins.getRootUrl()).thenReturn("http://localhost/");
        when(build.getEnvironment(buildListener)).thenReturn(environment);
        when(action.getLastBuiltRevision()).thenReturn(revision);
        when(revision.getSha1String()).thenReturn(sha1);
        doReturn(project).when(build).getProject();
        doReturn(project).when(build).getParent();
        doReturn(project).when(run).getParent();
        when(build.getFullDisplayName()).thenReturn("foo");
        when(build.getUrl()).thenReturn("foo");
        when(build.getActions(BuildData.class)).thenReturn(actions);
        when(environment.expand(anyString())).thenReturn(sha1);
        when(buildListener.getLogger()).thenReturn(logger);
        when(Secret.fromString("tiger")).thenReturn(secret);
        when(Secret.toString(secret)).thenReturn("tiger");
        when(secret.getPlainText()).thenReturn("tiger");
        when(HttpClientBuilder.create()).thenReturn(httpClientBuilder);
        when(httpClientBuilder.build()).thenReturn(client);
        when(client.execute(any(HttpUriRequest.class))).thenReturn(resp);
        when(resp.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(204);
        action.lastBuild = lastBuild;
        when(lastBuild.getMarked()).thenReturn(revision);

        when(com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
                any(),
                any(ItemGroup.class),
                any(Authentication.class),
                anyList()
        )).thenReturn(new ArrayList<>());
        when(httpNotifierSelector.select(any())).thenReturn(httpNotifier);

        sn = buildStashNotifier("http://localhost");
    }

    @AfterClass
    public static void close() {
        mockedJenkins.close();
        mockedCredentialsProvider.close();
        mockedSecret.close();
        mockedHttpClientBuilder.close();
    }

    @Test
    public void test_prebuild_normal() {
        assertTrue(sn.prebuild(build, buildListener));
    }

    @Test
    public void test_prebuild_null_revision() {
        when(build.getActions(BuildData.class)).thenReturn(Collections.singletonList(mock(BuildData.class)));
        assertTrue(sn.prebuild(build, buildListener));
    }

    @Test
    public void test_build_http_client_with_proxy() throws Exception {
        //given
        String address = "192.168.1.1";
        int port = 8080;
        String login = "admin";
        String password = "123";

        Secret secret = mock(Secret.class);
        when(Secret.fromString(password)).thenReturn(secret);
        when(Secret.toString(secret)).thenReturn(password);
        when(secret.getPlainText()).thenReturn(password);

        when(httpClientBuilder.setProxy(any(HttpHost.class))).thenReturn(httpClientBuilder);
        when(httpClientBuilder.setDefaultCredentialsProvider(any(CredentialsProvider.class))).thenReturn(httpClientBuilder);
        when(httpClientBuilder.setProxyAuthenticationStrategy(any(AuthenticationStrategy.class))).thenReturn(httpClientBuilder);

        jenkins.proxy = new ProxyConfiguration(address, port, login, password);
        PrintStream logger = mock(PrintStream.class);

        //when
        sn.getHttpClient(logger, build, "http://localhost");

        //then
        ArgumentCaptor<HttpHost> proxyCaptor = ArgumentCaptor.forClass(HttpHost.class);
        verify(httpClientBuilder).setProxy(proxyCaptor.capture());
        HttpHost proxy = proxyCaptor.getValue();
        //address
        assertThat(proxy.getHostName(), is(address));
        assertThat(proxy.getPort(), is(port));
        assertThat(proxy.getSchemeName(), is("http"));

        ArgumentCaptor<CredentialsProvider> credentialsProviderCaptor = ArgumentCaptor.forClass(CredentialsProvider.class);
        verify(httpClientBuilder).setDefaultCredentialsProvider(credentialsProviderCaptor.capture());
        CredentialsProvider credentialsProvider = credentialsProviderCaptor.getValue();
        org.apache.http.auth.UsernamePasswordCredentials credentials = (UsernamePasswordCredentials) credentialsProvider.getCredentials(new AuthScope(proxy));
        //credentials
        assertThat(credentials.getUserName(), is(login));
        assertThat(credentials.getPassword(), is(password));
    }

    @Test
    public void test_build_http_client_https() throws Exception {
        //given
        sn = new StashNotifier(
                "https://localhost",
                "scot",
                true,
                null,
                null,
                null,
                true,
                null,
                false,
                false,
                false,
                mock(JenkinsLocationConfiguration.class));

        PrintStream logger = mock(PrintStream.class);

        //when
        sn.getHttpClient(logger, build, "https://localhost");

        //then
        verify(httpClientBuilder).setSSLSocketFactory(any(SSLConnectionSocketFactory.class));
        verify(httpClientBuilder).setConnectionManager(any(HttpClientConnectionManager.class));
    }

    private void test_perform_buildstep(Result result,
                                        PrintStream logger,
                                        NotificationResult notificationResult,
                                        List<String> hashes) throws Exception {
        //given
        Launcher launcher = test_perform(result, logger, notificationResult, hashes);

        //when
        boolean perform = sn.perform(build, launcher, buildListener);

        //then
        assertThat(perform, is(true));
    }

    private void test_perform_simplebuildstep(Result result,
                                              PrintStream logger,
                                              NotificationResult notificationResult,
                                              List<String> hashes) throws Exception {
        //given
        Launcher launcher = test_perform(result, logger, notificationResult, hashes);

        //when
        sn.perform(build, workspace, launcher, buildListener);

        //then
        assertThat(build.getResult(), is(result));
    }

    private Launcher test_perform(Result result, PrintStream logger, NotificationResult notificationResult, List<String> hashes) throws Exception {
        when(buildListener.getLogger()).thenReturn(logger);
        when(build.getResult()).thenReturn(result);
        Launcher launcher = mock(Launcher.class);
        sn = spy(sn);
        doReturn(hashes).when(sn).lookupCommitSha1s(eq(build), nullable(FilePath.class), eq(buildListener));
        doReturn(notificationResult).when(sn).notifyStash(
                any(PrintStream.class),
                any(AbstractBuild.class),
                eq(sha1),
                eq(buildListener),
                any(StashBuildState.class)
        );
        return launcher;
    }

    @Test
    public void test_perform_build_step_success() throws Exception {
        //given
        ArrayList<String> hashes = new ArrayList<>();
        hashes.add(sha1);
        PrintStream logger = mock(PrintStream.class);

        //when
        test_perform_buildstep(Result.SUCCESS, logger, new NotificationResult(true, ""), hashes);

        //then
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(logger).println(messageCaptor.capture());
        assertThat(messageCaptor.getValue(), is(containsString("Notified Bitbucket for commit with id")));
    }

    @Test
    public void test_perform_build_step_success_for_unstable_build() throws Exception {
        //given
        sn = buildStashNotifier("http://localhost", false, true);
        ArrayList<String> hashes = new ArrayList<>();
        hashes.add(sha1);
        PrintStream logger = mock(PrintStream.class);

        //when
        test_perform_buildstep(Result.UNSTABLE, logger, new NotificationResult(true, ""), hashes);

        //then
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(logger, atLeastOnce()).println(messageCaptor.capture());
        List<String> values = messageCaptor.getAllValues();
        assertThat(values.get(0), is(containsString("UNSTABLE reported to Bitbucket as SUCCESSFUL")));
        assertThat(values.get(1), is(containsString("Notified Bitbucket for commit with id")));
    }

    @Test
    public void test_perform_build_step_aborted_without_notifying_stash() throws Exception {
        //given
        sn = buildStashNotifier("http://localhost", true, true);
        ArrayList<String> hashes = new ArrayList<>();
        hashes.add(sha1);
        PrintStream logger = mock(PrintStream.class);

        //when
        test_perform_buildstep(Result.ABORTED, logger, new NotificationResult(true, ""), hashes);

        //then
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(logger).println(messageCaptor.capture());
        assertThat(messageCaptor.getValue(), containsString("ABORTED"));
    }

    @Test
    public void test_perform_build_step_failure() throws Exception {
        //given
        ArrayList<String> hashes = new ArrayList<>();
        hashes.add(sha1);
        PrintStream logger = mock(PrintStream.class);

        //when
        test_perform_buildstep(Result.FAILURE, logger, new NotificationResult(false, ""), hashes);

        //then
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(logger).println(messageCaptor.capture());
        assertThat(messageCaptor.getValue(), is(containsString("Failed to notify Bitbucket for commit")));
    }

    @Test
    public void test_perform_build_step_not_built() throws Exception {
        //given
        ArrayList<String> hashes = new ArrayList<>();
        hashes.add(sha1);
        PrintStream logger = mock(PrintStream.class);

        //when
        test_perform_buildstep(Result.NOT_BUILT, logger, new NotificationResult(false, ""), hashes);

        //then
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(logger).println(messageCaptor.capture());
        assertThat(messageCaptor.getValue(), is(containsString("NOT BUILT")));
    }

    @Test
    public void test_perform_build_step_empty_hash() throws Exception {
        //given
        PrintStream logger = mock(PrintStream.class);
        when(buildListener.getLogger()).thenReturn(logger);
        when(build.getResult()).thenReturn(Result.SUCCESS);
        sn = spy(sn);
        doReturn(new ArrayList<String>()).when(sn).lookupCommitSha1s(eq(build), eq((FilePath) null), eq(buildListener));

        //when
        boolean perform = sn.perform(build, mock(Launcher.class), buildListener);

        //then
        assertThat(perform, is(true));
        verify(sn, never()).notifyStash(
                any(PrintStream.class),
                any(AbstractBuild.class),
                anyString(),
                eq(buildListener),
                any(StashBuildState.class)
        );
        verify(logger).println("found no commit info");
    }

    @Test
    public void test_perform_simple_build_step_success() throws Exception {
        //given
        ArrayList<String> hashes = new ArrayList<>();
        hashes.add(sha1);
        PrintStream logger = mock(PrintStream.class);

        //when
        test_perform_simplebuildstep(Result.SUCCESS, logger, new NotificationResult(true, ""), hashes);

        //then
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(logger).println(messageCaptor.capture());
        assertThat(messageCaptor.getValue(), is(containsString("Notified Bitbucket for commit with id")));
    }

    @Test
    public void test_perform_simple_build_step_failure() throws Exception {
        //given
        ArrayList<String> hashes = new ArrayList<>();
        hashes.add(sha1);
        PrintStream logger = mock(PrintStream.class);

        //when
        test_perform_simplebuildstep(Result.FAILURE, logger, new NotificationResult(false, ""), hashes);

        //then
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(logger).println(messageCaptor.capture());
        assertThat(messageCaptor.getValue(), is(containsString("Failed to notify Bitbucket for commit")));
    }

    @Test
    public void test_perform_simple_build_step_not_built() throws Exception {
        //given
        ArrayList<String> hashes = new ArrayList<>();
        hashes.add(sha1);
        PrintStream logger = mock(PrintStream.class);

        //when
        test_perform_simplebuildstep(Result.NOT_BUILT, logger, new NotificationResult(false, ""), hashes);

        //then
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(logger).println(messageCaptor.capture());
        assertThat(messageCaptor.getValue(), is(containsString("NOT BUILT")));
    }

    @Test
    public void test_perform_simple_build_step_empty_hash() throws Exception {
        //given
        PrintStream logger = mock(PrintStream.class);
        when(buildListener.getLogger()).thenReturn(logger);
        when(build.getResult()).thenReturn(Result.SUCCESS);
        sn = spy(sn);
        doReturn(new ArrayList<String>()).when(sn).lookupCommitSha1s(eq(build), eq((FilePath) null), eq(buildListener));

        //when
        sn.perform(build, workspace, mock(Launcher.class), buildListener);

        //then
        verify(sn, never()).notifyStash(
                any(PrintStream.class),
                any(AbstractBuild.class),
                anyString(),
                eq(buildListener),
                any(StashBuildState.class)
        );
        verify(logger).println("found no commit info");
    }

    @Test
    public void lookupCommitSha1s() throws Exception {
        //given
        try (MockedStatic<TokenMacro> tokenMacroMock = mockStatic(TokenMacro.class)) {
            tokenMacroMock.when(() -> TokenMacro.expandAll(any(), any(), any())).thenReturn(sha1);
            sn = new StashNotifier(
                    "https://localhost",
                    "scot",
                    true,
                    sha1,
                    null,
                    null,
                    true,
                    null,
                    false,
                    false,
                    false,
                    mock(JenkinsLocationConfiguration.class));

            //when
            Collection<String> hashes = sn.lookupCommitSha1s(build, null, buildListener);

            //then
            assertThat(hashes.size(), is(1));
            assertThat(hashes.iterator().next(), is(sha1));
        }
    }

    private void lookupCommitSha1s_Exception(Exception e) throws InterruptedException, MacroEvaluationException, IOException {
        //given
        PrintStream logger = mock(PrintStream.class);
        when(buildListener.getLogger()).thenReturn(logger);
        try (MockedStatic<TokenMacro> tokenMacroMock = mockStatic(TokenMacro.class)) {
            tokenMacroMock.when(() -> TokenMacro.expandAll(any(), any(), any())).thenThrow(e);
            sn = new StashNotifier(
                    "http://localhost",
                    "scot",
                    true,
                    sha1,
                    null,
                    null,
                    true,
                    null,
                    false,
                    false,
                    false,
                    mock(JenkinsLocationConfiguration.class));

            //when
            Collection<String> hashes = sn.lookupCommitSha1s(build, null, buildListener);

            //then
            assertThat(hashes.isEmpty(), is(true));
            verify(logger).println("Unable to expand commit SHA value");
        }
    }

    @Test
    public void test_lookupCommitSha1s_IOException() throws Exception {
        lookupCommitSha1s_Exception(new IOException("BOOM"));
    }

    @Test
    public void test_lookupCommitSha1s_InterruptedException() throws Exception {
        lookupCommitSha1s_Exception(new InterruptedException("BOOM"));
    }

    @Test
    public void test_lookupCommitSha1s_MacroEvaluationException() throws Exception {
        lookupCommitSha1s_Exception(new MacroEvaluationException("BOOM"));
    }

    @Test
    public void test_getBuildDescription() {
        //given
        AbstractBuild build = mock(AbstractBuild.class);
        when(build.getDescription()).thenReturn("some description");

        //when
        String description = sn.getBuildDescription(build, StashBuildState.FAILED);

        //then
        assertThat(description, is("some description"));
    }

    private String getBuildDescriptionWhenBuildDescriptionIsNull(StashBuildState buildState) {
        return sn.getBuildDescription(mock(AbstractBuild.class), buildState);
    }

    @Test
    public void test_getBuildDescription_state() {
        assertThat(getBuildDescriptionWhenBuildDescriptionIsNull(StashBuildState.SUCCESSFUL), is("built by Jenkins @ http://localhost/"));
        assertThat(getBuildDescriptionWhenBuildDescriptionIsNull(StashBuildState.FAILED), is("built by Jenkins @ http://localhost/"));
        assertThat(getBuildDescriptionWhenBuildDescriptionIsNull(StashBuildState.INPROGRESS), is("building on Jenkins @ http://localhost/"));
    }

    @Test
    public void test_getPushedBuildState_overwritten() {
        //given
        StashBuildState state = StashBuildState.SUCCESSFUL;

        sn = new StashNotifier(
                "",
                "scot",
                true,
                null,
                state.name(),
                null,
                true,
                null,
                true,
                false,
                false,
                mock(JenkinsLocationConfiguration.class));

        //when
        StashBuildState pushedBuildStatus = sn.getPushedBuildStatus(StashBuildState.FAILED);

        //then
        assertThat(pushedBuildStatus, is(state));
    }

    @Test
    public void test_getPushedBuildState_not_overwritten() {
        //given
        sn = new StashNotifier(
                "",
                "scot",
                true,
                null,
                null,
                null,
                true,
                null,
                true,
                false,
                false,
                mock(JenkinsLocationConfiguration.class));

        //when
        StashBuildState pushedBuildStatus = sn.getPushedBuildStatus(StashBuildState.FAILED);

        //then
        assertThat(pushedBuildStatus, is(StashBuildState.FAILED));
    }

    @Test
    public void test_getBuildName_overwritten() {
        //given
        when(run.getFullDisplayName()).thenReturn("default-name");
        String name = "custom-name";

        sn = new StashNotifier(
                "",
                "scot",
                true,
                null,
                null,
                name,
                true,
                null,
                true,
                false,
                false,
                mock(JenkinsLocationConfiguration.class));

        //when
        String buildName = sn.getBuildName(run);

        //then
        assertThat(buildName, is(name));
    }

    @Test
    public void test_getBuildName_not_overwritten() {
        //given
        when(run.getFullDisplayName()).thenReturn("default-name");

        sn = new StashNotifier(
                "",
                "scot",
                true,
                null,
                null,
                null,
                true,
                null,
                true,
                false,
                false,
                mock(JenkinsLocationConfiguration.class));

        //when
        String buildName = sn.getBuildName(run);

        //then
        assertThat(buildName, is("default-name"));
    }

    @Test
    public void test_getBuildKey() throws Exception {
        //given
        String key = "someKey";
        PrintStream logger = mock(PrintStream.class);
        when(buildListener.getLogger()).thenReturn(logger);
        try (MockedStatic<TokenMacro> tokenMacroMock = mockStatic(TokenMacro.class)) {
            tokenMacroMock.when(() -> TokenMacro.expandAll(any(), any(), any())).thenReturn(key);

            sn = new StashNotifier(
                    "",
                    "scot",
                    true,
                    null,
                    null,
                    "build-name",
                    true,
                    key,
                    true,
                    false,
                    false,
                    mock(JenkinsLocationConfiguration.class));

            //when
            String buildKey = sn.getBuildKey(build, buildListener);

            //then
            assertThat(buildKey, is(key));
        }
    }

    @Test
    public void test_getBuildKey_withBuildName() {
        //given
        String parentName = "someKey";
        int number = 11;
        String buildName = "buildName";

        when(build.getParent().getName()).thenReturn(parentName);
        when(build.getNumber()).thenReturn(number);

        sn = new StashNotifier(
                "",
                "scot",
                true,
                null,
                null,
                buildName,
                true,
                null,
                true,
                false,
                false,
                mock(JenkinsLocationConfiguration.class));

        //when
        String buildKey = sn.getBuildKey(build, buildListener);

        //then
        assertThat(buildKey, is(StringEscapeUtils.escapeJavaScript(parentName + "-" + number + "-" + jenkins.getRootUrl() + "-" + buildName)));
    }

    @Test
    public void test_getRunKey() throws Exception {
        //given
        String key = "someKey";
        PrintStream logger = mock(PrintStream.class);
        when(buildListener.getLogger()).thenReturn(logger);
        final File tempDir = File.createTempFile("stashNotifier", null);
        when(run.getRootDir()).thenReturn(tempDir);
        try (MockedStatic<TokenMacro> tokenMacroMock = mockStatic(TokenMacro.class)) {
            tokenMacroMock.when(() -> TokenMacro.expandAll(any(), any(), any(), any()))
                    .thenReturn(key);

            sn = new StashNotifier(
                    "",
                    "scot",
                    true,
                    null,
                    null,
                    null,
                    true,
                    key,
                    true,
                    false,
                    false,
                    mock(JenkinsLocationConfiguration.class));

            //when
            String buildKey = sn.getBuildKey(run, buildListener);

            //then
            assertThat(buildKey, is(key));
        }
    }

    private void getBuildKey_Exception(Exception e) throws InterruptedException, MacroEvaluationException, IOException {
        //given
        String key = "someKey";
        PrintStream logger = mock(PrintStream.class);
        when(buildListener.getLogger()).thenReturn(logger);
        try (MockedStatic<TokenMacro> tokenMacroMock = mockStatic(TokenMacro.class)) {
            tokenMacroMock.when(() -> TokenMacro.expandAll(any(), any(), any())).thenThrow(e);

            sn = new StashNotifier(
                    "",
                    "scot",
                    true,
                    null,
                    null,
                    null,
                    true,
                    key,
                    true,
                    false,
                    false,
                    mock(JenkinsLocationConfiguration.class));

            //when
            String buildKey = sn.getBuildKey(build, buildListener);

            //then
            assertThat(buildKey, is("null-0-http:\\/\\/localhost\\/"));
            verify(logger).println("Cannot expand build key from parameter. Processing with default build key");
        }
    }

    private void getRunKey_Exception(Exception e) throws InterruptedException, MacroEvaluationException, IOException {
        //given
        String key = "someKey";
        PrintStream logger = mock(PrintStream.class);
        when(buildListener.getLogger()).thenReturn(logger);
        final File tempDir = File.createTempFile("stashNotifier", null);
        when(run.getRootDir()).thenReturn(tempDir);
        try (MockedStatic<TokenMacro> tokenMacroMock = mockStatic(TokenMacro.class)) {
            tokenMacroMock.when(() -> TokenMacro.expandAll(any(), any(), any(), any()))
                    .thenThrow(e);

            sn = new StashNotifier(
                    "",
                    "scot",
                    true,
                    null,
                    null,
                    null,
                    true,
                    key,
                    true,
                    false,
                    false,
                    mock(JenkinsLocationConfiguration.class));

            //when
            String buildKey = sn.getBuildKey(run, buildListener);

            //then
            assertThat(buildKey, is("null-0-http:\\/\\/localhost\\/"));
            verify(logger).println(
                    "Cannot expand build key from parameter. Processing with default build key");
        }
    }

    @Test
    public void test_getBuildKey_IOException() throws Exception {
        getBuildKey_Exception(new IOException("BOOM"));
    }

    @Test
    public void test_getBuildKey_InterruptedException() throws Exception {
        getBuildKey_Exception(new InterruptedException("BOOM"));
    }

    @Test
    public void test_getBuildKey_MacroEvaluationException() throws Exception {
        getBuildKey_Exception(new MacroEvaluationException("BOOM"));
    }

    @Test
    public void test_getRunKey_IOException() throws Exception {
        getRunKey_Exception(new IOException("BOOM"));
    }

    @Test
    public void test_getRunKey_InterruptedException() throws Exception {
        getRunKey_Exception(new InterruptedException("BOOM"));
    }

    @Test
    public void test_getRunKey_MacroEvaluationException() throws Exception {
        getRunKey_Exception(new MacroEvaluationException("BOOM"));
    }

    private NotificationResult notifyStash(int statusCode) throws Exception {
        sn = spy(this.sn);
        PrintStream logger = mock(PrintStream.class);
        DisplayURLProvider displayURLProvider = mock(DisplayURLProvider.class);
        when(displayURLProvider.getRunURL(run)).thenReturn("http://localhost");
        when(buildListener.getLogger()).thenReturn(logger);
        doReturn("someKey1").when(sn).getBuildKey(eq(build), eq(buildListener));
        HttpPost httpPost = mock(HttpPost.class);
        CloseableHttpResponse resp = mock(CloseableHttpResponse.class);
        StatusLine sl = mock(StatusLine.class);
        when(sl.getStatusCode()).thenReturn(statusCode);
        when(resp.getStatusLine()).thenReturn(sl);
        when(resp.getEntity()).thenReturn(new StringEntity(""));
        when(client.execute(eq(httpPost))).thenReturn(resp);
        try (MockedStatic<TokenMacro> tokenMacroMock = mockStatic(TokenMacro.class); MockedStatic<DisplayURLProvider> displayURLProviderMock = mockStatic(DisplayURLProvider.class)) {
            displayURLProviderMock.when(DisplayURLProvider::get).thenReturn(displayURLProvider);
            tokenMacroMock.when(() -> TokenMacro.expandAll(any(), any(), any())).thenReturn("http://localhost");
            doReturn(client).when(sn).getHttpClient(any(PrintStream.class), any(AbstractBuild.class), anyString());
            return sn.notifyStash(logger, build, sha1, buildListener, StashBuildState.FAILED);
        }
    }

    @Test
    public void notifyStashDelegatesToHttpNotifier() throws Exception {
        NotificationResult result = NotificationResult.newFailure("some value for test");
        when(httpNotifier.send(any(), any(), any(), any())).thenReturn(result);
        NotificationResult notificationResult = notifyStash(204);
        verify(httpNotifier).send(any(), any(), any(), any());
        assertThat(notificationResult, equalTo(result));
    }

    @Test
    public void setBuildStatus_string() {
      sn.setBuildStatus("SUCCESSFUL");
      assertThat(sn.getBuildStatus(), equalTo(StashBuildState.SUCCESSFUL));

      sn.setBuildStatus("FAILED");
      assertThat(sn.getBuildStatus(), equalTo(StashBuildState.FAILED));

      sn.setBuildStatus("INPROGRESS");
      assertThat(sn.getBuildStatus(), equalTo(StashBuildState.INPROGRESS));
    }

    @Test
    public void setBuildStatus_stashBuildState() {
      sn.setBuildStatus(StashBuildState.SUCCESSFUL);
      assertThat(sn.getBuildStatus(), equalTo(StashBuildState.SUCCESSFUL));

      sn.setBuildStatus(StashBuildState.FAILED);
      assertThat(sn.getBuildStatus(), equalTo(StashBuildState.FAILED));

      sn.setBuildStatus(StashBuildState.INPROGRESS);
      assertThat(sn.getBuildStatus(), equalTo(StashBuildState.INPROGRESS));
    }

    @Test
    public void setBuildStatus_null() {
      sn.setBuildStatus(null);
      assertThat(sn.getBuildStatus(), nullValue());

      sn.setBuildStatus(StashBuildState.SUCCESSFUL);
      assertThat(sn.getBuildStatus(), equalTo(StashBuildState.SUCCESSFUL));

      sn.setBuildStatus(null);
      assertThat(sn.getBuildStatus(), equalTo(StashBuildState.SUCCESSFUL));
    }
}
