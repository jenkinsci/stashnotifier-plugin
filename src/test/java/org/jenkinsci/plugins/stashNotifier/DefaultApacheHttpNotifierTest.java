package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
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
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.File;
import java.io.PrintStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Secret.class, Jenkins.class, HttpClientBuilder.class, TokenMacro.class, CredentialsMatchers.class, com.cloudbees.plugins.credentials.CredentialsProvider.class, AbstractProject.class})
@PowerMockIgnore("javax.net.ssl.*")
public class DefaultApacheHttpNotifierTest {

    final static String sha1 = "1234567890123456789012345678901234567890";
    private CloseableHttpClient client;
    private final HttpNotifier httpNotifier = new DefaultApacheHttpNotifier();

    BuildListener buildListener;
    AbstractBuild<?, ?> build;
    Run<?, ?> run;
    FilePath workspace;

    @Before
    public void setUp() throws Exception {
        PowerMockito.mockStatic(Secret.class);
        PowerMockito.mockStatic(Jenkins.class);
        PowerMockito.mockStatic(HttpClientBuilder.class);
        PowerMockito.mockStatic(TokenMacro.class);
        PowerMockito.mockStatic(com.cloudbees.plugins.credentials.CredentialsProvider.class);

        buildListener = mock(BuildListener.class);
        Jenkins jenkins = mock(Jenkins.class);
        build = mock(AbstractBuild.class);
        run = mock(Run.class);
        AbstractProject project = PowerMockito.mock(AbstractProject.class);
        File file = mock(File.class);
        when(file.getPath()).thenReturn("/tmp/fake/path");
        FilePath filePath = new FilePath(file);
        PowerMockito.when(project.getSomeWorkspace()).thenReturn(filePath);
        workspace = project.getSomeWorkspace();
        EnvVars environment = mock(EnvVars.class);
        PrintStream logger = System.out;
        Secret secret = mock(Secret.class);
        HttpClientBuilder httpClientBuilder = PowerMockito.mock(HttpClientBuilder.class);
        client = mock(CloseableHttpClient.class);
        CloseableHttpResponse resp = mock(CloseableHttpResponse.class);
        StatusLine statusLine = mock(StatusLine.class);
        BuildData action = mock(BuildData.class);
        Revision revision = mock(Revision.class);
        Build lastBuild = mock(Build.class);
        List<BuildData> actions = Collections.singletonList(action);

        when(Jenkins.getInstance()).thenReturn(jenkins);
        when(jenkins.getRootUrl()).thenReturn("http://localhost/");
        when(build.getEnvironment(buildListener)).thenReturn(environment);
        when(action.getLastBuiltRevision()).thenReturn(revision);
        when(revision.getSha1String()).thenReturn(sha1);
        when(build.getProject()).thenReturn(project);
        when(run.getParent()).thenReturn(project);
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

        when(TokenMacro.expandAll(build, buildListener, "test-project")).thenReturn("prepend-key");
        when(com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
                any(),
                any(ItemGroup.class),
                any(Authentication.class),
                anyList()
        )).thenReturn(new ArrayList<>());
    }

    private NotificationResult notifyStash(int statusCode) throws Exception {
        PrintStream logger = mock(PrintStream.class);
        URI uri = BuildStatusUriFactory.create("http://localhost", "df02f57eea1cda72fa2412102f061dd7f6188e98");
        when(buildListener.getLogger()).thenReturn(logger);
        CloseableHttpResponse resp = mock(CloseableHttpResponse.class);
        StatusLine sl = mock(StatusLine.class);
        when(sl.getStatusCode()).thenReturn(statusCode);
        when(resp.getStatusLine()).thenReturn(sl);
        when(resp.getEntity()).thenReturn(new StringEntity(""));
        when(client.execute(any(HttpPost.class))).thenReturn(resp);
        return httpNotifier.send(uri, new JSONObject(), new NotificationSettings(false, false,null), new NotificationContext(logger, "some-build#15"));
    }

    @Test
    public void notifyStash_success() throws Exception {
        NotificationResult notificationResult = notifyStash(204);
        assertThat(notificationResult.indicatesSuccess, is(true));
    }

    @Test
    public void notifyStash_fail() throws Exception {
        NotificationResult notificationResult = notifyStash(400);
        assertThat(notificationResult.indicatesSuccess, is(false));
    }
}
