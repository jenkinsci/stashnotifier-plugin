package org.jenkinsci.plugins.stashNotifier;

import hudson.FilePath;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.FreeStyleProject;
import hudson.model.Run;
import jenkins.branch.MultiBranchProject;
import jenkins.model.JenkinsLocationConfiguration;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StashNotifierBuildsApiTest {

    @Test
    void shouldUseGlobalApiByDefaultAndAllowLocalOverride() {
        StashNotifier notifier = newNotifier();
        StashNotifier.DescriptorImpl globalDescriptor = mock(StashNotifier.DescriptorImpl.class);
        doReturn(globalDescriptor).when(notifier).getGlobalDescriptor();
        when(globalDescriptor.isDefaultUseBuildsApi()).thenReturn(true);

        assertThat(notifier.isBuildsApiEnabled(), is(true));

        notifier.setUseBuildsApi(false);

        assertThat(notifier.isBuildsApiEnabled(), is(false));
    }

    @Test
    void shouldRequireRepositoryCoordinatesForBuildsApi() {
        StashNotifier notifier = buildsApiNotifier(null, "repository");

        IllegalArgumentException missingProject = assertThrows(
                IllegalArgumentException.class,
                notifier::validateBuildsApiConfiguration);
        assertThat(
                missingProject.getMessage(),
                is("bitbucketProjectKey is required when useBuildsApi is true"));

        notifier.setBitbucketProjectKey("PROJECT");
        notifier.setRepositorySlug(" ");

        IllegalArgumentException missingRepository = assertThrows(
                IllegalArgumentException.class,
                notifier::validateBuildsApiConfiguration);
        assertThat(
                missingRepository.getMessage(),
                is("repositorySlug is required when useBuildsApi is true"));
    }

    @Test
    void shouldCreateBuildsApiUriFromExpandedCoordinates() throws Exception {
        StashNotifier notifier = buildsApiNotifier("$PROJECT", "$REPOSITORY");
        AbstractBuild<?, ?> build = mock(AbstractBuild.class);
        BuildListener listener = mock(BuildListener.class);
        doReturn("PROJECT").when(notifier).expandValue(build, listener, "$PROJECT");
        doReturn("repository").when(notifier).expandValue(build, listener, "$REPOSITORY");

        URI actual = notifier.createBuildStatusUri(
                "https://bitbucket.example/bitbucket",
                "25a4b3c9",
                build,
                listener);

        assertThat(actual, equalTo(URI.create(
                "https://bitbucket.example/bitbucket/rest/api/latest/projects/PROJECT/repos/repository/commits/25a4b3c9/builds")));
    }

    @Test
    void shouldRejectEmptyExpandedRepositoryCoordinates() throws Exception {
        StashNotifier notifier = buildsApiNotifier("$PROJECT", "repository");
        AbstractBuild<?, ?> build = mock(AbstractBuild.class);
        BuildListener listener = mock(BuildListener.class);
        doReturn(" ").when(notifier).expandValue(build, listener, "$PROJECT");
        doReturn("repository").when(notifier).expandValue(build, listener, "repository");

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> notifier.createBuildStatusUri("https://bitbucket.example", "abc", build, listener));

        assertThat(error.getMessage(), is("bitbucketProjectKey must not be empty"));
    }

    @Test
    void shouldUseMultibranchProjectAsBuildParent() {
        StashNotifier notifier = buildsApiNotifier("PROJECT", "repository");
        Run<?, ?> run = mock(Run.class);
        MultiBranchProject<?, ?> multibranchProject = mock(MultiBranchProject.class);
        FreeStyleProject branchJob = new FreeStyleProject(multibranchProject, "branch");
        doReturn(branchJob).when(run).getParent();
        when(multibranchProject.getFullName()).thenReturn("folder/application");

        assertThat(notifier.getBuildParent(run), is("folder/application"));
    }

    @Test
    void shouldAddParentOnlyToBuildsApiPayload() {
        StashNotifier notifier = buildsApiNotifier("PROJECT", "repository");
        Run<?, ?> run = mock(Run.class);
        BuildListener listener = mock(BuildListener.class);
        doReturn("branch-key").when(notifier).getBuildKey(run, listener);
        doReturn("application").when(notifier).getBuildParent(run);
        notifier.setBuildName("build-name");
        notifier.setBuildUrl("https://jenkins.example/job/1");
        when(run.getDescription()).thenReturn("description");

        JSONObject buildsApiPayload = notifier.createNotificationPayload(run, StashBuildState.SUCCESSFUL, listener);
        notifier.setUseBuildsApi(false);
        JSONObject standardPayload = notifier.createNotificationPayload(run, StashBuildState.SUCCESSFUL, listener);

        assertThat(buildsApiPayload.getString("parent"), is("application"));
        assertThat(standardPayload.containsKey("parent"), is(false));
    }

    @Test
    void shouldSendBuildsApiNotification() throws Exception {
        StashNotifier notifier = buildsApiNotifier("PROJECT", "repository");
        AbstractBuild<?, ?> run = mock(AbstractBuild.class);
        AbstractProject<?, ?> job = mock(AbstractProject.class);
        BuildListener listener = mock(BuildListener.class);
        HttpNotifier httpNotifier = mock(HttpNotifier.class);
        HttpNotifierSelector selector = mock(HttpNotifierSelector.class);
        StashNotifier.DescriptorImpl globalDescriptor = mock(StashNotifier.DescriptorImpl.class);
        NotificationResult expectedResult = NotificationResult.newSuccess();

        doReturn(job).when(run).getParent();
        when(job.getFullName()).thenReturn("folder/application/branch");
        when(run.getExternalizableId()).thenReturn("folder/application/branch#1");
        when(run.getWorkspace()).thenReturn(mock(FilePath.class));
        when(listener.getLogger()).thenReturn(System.out);
        when(httpNotifier.send(any(), any(), any(), any())).thenReturn(expectedResult);
        when(selector.select(any())).thenReturn(httpNotifier);
        doReturn(globalDescriptor).when(notifier).getGlobalDescriptor();
        doReturn("build-key").when(notifier).getBuildKey(run, listener);
        doReturn("folder/application").when(notifier).getBuildParent(run);
        doReturn("PROJECT").when(notifier).expandValue(run, listener, "PROJECT");
        doReturn("repository").when(notifier).expandValue(run, listener, "repository");
        notifier.setHttpNotifierSelector(selector);
        notifier.setStashServerBaseUrl("https://bitbucket.example");
        notifier.setBuildName("build-name");
        notifier.setBuildUrl("https://jenkins.example/job/1");
        when(run.getDescription()).thenReturn("description");

        NotificationResult actualResult = notifier.notifyStash(
                System.out,
                run,
                "25a4b3c9",
                listener,
                StashBuildState.SUCCESSFUL);

        ArgumentCaptor<URI> uri = ArgumentCaptor.forClass(URI.class);
        ArgumentCaptor<JSONObject> payload = ArgumentCaptor.forClass(JSONObject.class);
        verify(httpNotifier).send(uri.capture(), payload.capture(), any(), any());
        assertThat(actualResult, is(expectedResult));
        assertThat(uri.getValue(), equalTo(URI.create(
                "https://bitbucket.example/rest/api/latest/projects/PROJECT/repos/repository/commits/25a4b3c9/builds")));
        assertThat(payload.getValue().getString("parent"), is("folder/application"));
    }

    private StashNotifier buildsApiNotifier(String projectKey, String repositorySlug) {
        StashNotifier notifier = newNotifier();
        notifier.setUseBuildsApi(true);
        notifier.setBitbucketProjectKey(projectKey);
        notifier.setRepositorySlug(repositorySlug);
        return notifier;
    }

    private StashNotifier newNotifier() {
        return spy(new StashNotifier(
                null,
                null,
                false,
                null,
                null,
                null,
                null,
                false,
                null,
                false,
                false,
                false,
                mock(JenkinsLocationConfiguration.class)));
    }
}
