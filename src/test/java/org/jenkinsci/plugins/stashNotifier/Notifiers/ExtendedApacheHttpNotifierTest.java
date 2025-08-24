package org.jenkinsci.plugins.stashNotifier.Notifiers;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.ItemGroup;
import hudson.model.Run;
import hudson.plugins.git.Revision;
import hudson.plugins.git.util.Build;
import hudson.plugins.git.util.BuildData;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.apache.http.StatusLine;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jenkinsci.plugins.stashNotifier.*;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.PrintStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ExtendedApacheHttpNotifierTest {

    final static String sha1 = "1234567890123456789012345678901234567890";
    private static CloseableHttpClient client;
    private static MockedStatic<Jenkins> mockedJenkins;
    private static MockedStatic<CredentialsProvider> mockedCredentialsProvider;
    private static MockedStatic<Secret> mockedSecret;
    private static MockedStatic<HttpClientBuilder> mockedStaticHttpClientBuilder;
    private static MockedStatic<TokenMacro> mockedTokenMacro;
    private final HttpNotifier httpNotifier = new ExtendedApacheHttpNotifier();

    private static BuildListener buildListener;
    private HttpClientBuilder httpClientBuilder;

    @BeforeClass
    public static void setUp() throws Exception {
        mockedSecret = mockStatic(Secret.class);
        mockedJenkins = mockStatic(Jenkins.class);
        mockedStaticHttpClientBuilder = mockStatic(HttpClientBuilder.class);
        mockedTokenMacro = mockStatic(TokenMacro.class);
        mockedCredentialsProvider = mockStatic(com.cloudbees.plugins.credentials.CredentialsProvider.class);

        buildListener = mock(BuildListener.class);
        Jenkins jenkins = mock(Jenkins.class);
        AbstractBuild<?, ?> build = mock(AbstractBuild.class);
        Run<?, ?> run = mock(Run.class);

        AbstractProject<?, ?> project = mock(AbstractProject.class);
        File file = mock(File.class);
        when(file.getPath()).thenReturn("/tmp/fake/path");
        FilePath filePath = new FilePath(file);
        when(project.getSomeWorkspace()).thenReturn(filePath);
        FilePath workspace = project.getSomeWorkspace();
        EnvVars environment = mock(EnvVars.class);
        PrintStream logger = System.out;
        Secret secret = mock(Secret.class);

        client = mock(CloseableHttpClient.class);
        CloseableHttpResponse resp = mock(CloseableHttpResponse.class);
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
        doReturn(project).when(run).getParent();
        when(build.getFullDisplayName()).thenReturn("foo");
        when(build.getUrl()).thenReturn("foo");
        when(build.getActions(BuildData.class)).thenReturn(actions);
        when(environment.expand(anyString())).thenReturn(sha1);
        when(buildListener.getLogger()).thenReturn(logger);
        when(Secret.fromString("tiger")).thenReturn(secret);
        when(Secret.toString(secret)).thenReturn("tiger");
        when(secret.getPlainText()).thenReturn("tiger");
        when(client.execute(any(HttpUriRequest.class))).thenReturn(resp);
        when(resp.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(204);
        action.lastBuild = lastBuild;
        when(lastBuild.getMarked()).thenReturn(revision);

        when(TokenMacro.expandAll(build, buildListener, "test-project")).thenReturn("prepend-key");
        when(CredentialsProvider.lookupCredentials(
                any(),
                any(ItemGroup.class),
                any(Authentication.class),
                anyList()
        )).thenReturn(new ArrayList<>());
    }

    @AfterClass
    public static void close() {
        mockedJenkins.close();
        mockedCredentialsProvider.close();
        mockedSecret.close();
        mockedStaticHttpClientBuilder.close();
        mockedTokenMacro.close();
    }

    @Before
    public void before() {
        httpClientBuilder = mock(HttpClientBuilder.class);
        when(HttpClientBuilder.create()).thenReturn(httpClientBuilder);
        when(httpClientBuilder.build()).thenReturn(client);
    }

    @Test
    public void notifyStash_noSlug_success() throws Exception {
        NotificationResult notificationResult = notifyStash(204, "", "");
        assertThat(notificationResult.indicatesSuccess, is(true));
    }

    @Test
    public void notifyStash_noSlug_fail() throws Exception {
        NotificationResult notificationResult = notifyStash(400, "", "");
        assertThat(notificationResult.indicatesSuccess, is(false));
    }
    @Test
    public void notifyStash_Slug_success() throws Exception {
        NotificationResult notificationResult = notifyStash(204, "testProject", "someslug");
        assertThat(notificationResult.indicatesSuccess, is(true));
    }

    @Test
    public void notifyStash_Slug_fail() throws Exception {
        NotificationResult notificationResult = notifyStash(400, "testProject", "someslug");
        assertThat(notificationResult.indicatesSuccess, is(false));
    }

    @Test
    public void notifyStashUsesRequestParametersNoSlug() throws Exception {
        notifyStash(204, "", "");

        final ArgumentCaptor<RequestConfig> captor = ArgumentCaptor.forClass(RequestConfig.class);
        verify(httpClientBuilder).setDefaultRequestConfig(captor.capture());

        final RequestConfig config = captor.getValue();
        assertThat(config.getSocketTimeout(), is(60_000));
        assertThat(config.getConnectTimeout(), is(60_000));
        assertThat(config.getConnectionRequestTimeout(), is(60_000));
        assertThat(config.getCookieSpec(), is(CookieSpecs.STANDARD));
    }

    @Test
    public void notifyStashUsesRequestParametersSlug() throws Exception {
        notifyStash(204, "testProject", "someslug");

        final ArgumentCaptor<RequestConfig> captor = ArgumentCaptor.forClass(RequestConfig.class);
        verify(httpClientBuilder).setDefaultRequestConfig(captor.capture());

        final RequestConfig config = captor.getValue();
        assertThat(config.getSocketTimeout(), is(60_000));
        assertThat(config.getConnectTimeout(), is(60_000));
        assertThat(config.getConnectionRequestTimeout(), is(60_000));
        assertThat(config.getCookieSpec(), is(CookieSpecs.STANDARD));
    }

    @NonNull
    private NotificationResult notifyStash(int statusCode, String projectKey, String slug) throws Exception {
        PrintStream logger = mock(PrintStream.class);
        URI uri = BuildStatusUriFactory.create("http://localhost", projectKey, slug, "df02f57eea1cda72fa2412102f061dd7f6188e98");
        when(buildListener.getLogger()).thenReturn(logger);
        CloseableHttpResponse resp = mock(CloseableHttpResponse.class);
        StatusLine sl = mock(StatusLine.class);
        when(sl.getStatusCode()).thenReturn(statusCode);
        when(resp.getStatusLine()).thenReturn(sl);
        when(resp.getEntity()).thenReturn(new StringEntity(""));
        when(client.execute(any(HttpPost.class))).thenReturn(resp);
        BuildInformation information = new BuildInformation("1", 30000, StashBuildState.SUCCESSFUL, "ci-testbuild", uri.toString(), "ci-testbuild", "A Testbuild for Stash/Bitbucket");
        return httpNotifier.send(uri, new NotificationSettings(false, null), new NotificationContext(logger, "some-build#15", information));
    }
}
