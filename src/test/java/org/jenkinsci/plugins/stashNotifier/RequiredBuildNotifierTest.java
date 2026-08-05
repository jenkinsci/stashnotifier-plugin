package org.jenkinsci.plugins.stashNotifier;

import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.ItemGroup;
import hudson.model.Job;
import hudson.model.Run;
import jenkins.branch.MultiBranchProject;
import jenkins.model.JenkinsLocationConfiguration;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RequiredBuildNotifierTest {

    @Test
    void shouldExposeRequiredAndInheritedConfiguration() {
        try (MockedStatic<JenkinsLocationConfiguration> configuration = mockStatic(JenkinsLocationConfiguration.class)) {
            RequiredBuildNotifier notifier = new RequiredBuildNotifier("PROJ", "my-repo");
            notifier.setBuildKey("build-key");
            notifier.setBuildName("build-name");
            notifier.setBuildUrl("https://jenkins.example/job/1");

            assertThat(notifier.getBitbucketProjectKey(), is("PROJ"));
            assertThat(notifier.getRepositorySlug(), is("my-repo"));
            assertThat(notifier.getBuildKey(), is("build-key"));
            assertThat(notifier.getBuildName(), is("build-name"));
            assertThat(notifier.getBuildUrl(), is("https://jenkins.example/job/1"));
        }
    }

    @Test
    void shouldCreateRequiredBuildUriFromExpandedCoordinates() throws Exception {
        RequiredBuildNotifier notifier = newNotifier("$PROJECT", "$REPOSITORY");
        AbstractBuild<?, ?> build = mock(AbstractBuild.class);
        BuildListener listener = mock(BuildListener.class);
        doReturn("PROJ").when(notifier).expandValue(build, listener, "$PROJECT");
        doReturn("my-repo").when(notifier).expandValue(build, listener, "$REPOSITORY");

        URI actual = notifier.createBuildStatusUri(
                "https://bitbucket.example/bitbucket",
                "25a4b3c9",
                build,
                listener);

        assertThat(actual, equalTo(URI.create(
                "https://bitbucket.example/bitbucket/rest/api/latest/projects/PROJ/repos/my-repo/commits/25a4b3c9/builds")));
    }

    @Test
    void shouldRejectEmptyExpandedCoordinates() throws Exception {
        RequiredBuildNotifier notifier = newNotifier("$PROJECT", "repo");
        AbstractBuild<?, ?> build = mock(AbstractBuild.class);
        BuildListener listener = mock(BuildListener.class);
        doReturn(" ").when(notifier).expandValue(build, listener, "$PROJECT");
        doReturn("repo").when(notifier).expandValue(build, listener, "repo");

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> notifier.createBuildStatusUri("https://bitbucket.example", "abc", build, listener));

        assertThat(error.getMessage(), is("Bitbucket project key must not be empty"));
    }

    @Test
    void shouldUseJobFullNameAsParentForRegularJob() {
        RequiredBuildNotifier notifier = newNotifier("PROJ", "repo");
        Run<?, ?> run = mock(Run.class);
        Job<?, ?> job = mock(Job.class);
        doReturn(job).when(run).getParent();
        when(job.getFullName()).thenReturn("folder/job");

        assertThat(notifier.getBuildParent(run), is("folder/job"));
    }

    @Test
    void shouldUseMultibranchProjectFullNameAsParent() {
        RequiredBuildNotifier notifier = newNotifier("PROJ", "repo");
        Run<?, ?> run = mock(Run.class);
        Job<?, ?> branchJob = mock(Job.class);
        MultiBranchProject<?, ?> multibranchProject = mock(MultiBranchProject.class);
        doReturn(branchJob).when(run).getParent();
        doReturn(multibranchProject).when(branchJob).getParent();
        when(multibranchProject.getFullName()).thenReturn("folder/application");

        assertThat(notifier.getBuildParent(run), is("folder/application"));
    }

    @Test
    void shouldAddParentToPayload() {
        RequiredBuildNotifier notifier = newNotifier("PROJ", "repo");
        Run<?, ?> run = mock(Run.class);
        BuildListener listener = mock(BuildListener.class);
        doReturn("branch-key").when(notifier).getBuildKey(run, listener);
        doReturn("application").when(notifier).getBuildParent(run);
        notifier.setBuildName("build-name");
        notifier.setBuildUrl("https://jenkins.example/job/1");
        when(run.getDescription()).thenReturn("description");

        JSONObject payload = notifier.createNotificationPayload(run, StashBuildState.SUCCESSFUL, listener);

        assertThat(payload.getString("state"), is("SUCCESSFUL"));
        assertThat(payload.getString("key"), is("branch-key"));
        assertThat(payload.getString("parent"), is("application"));
    }

    @Test
    void shouldSendRequiredBuildNotification() throws Exception {
        RequiredBuildNotifier notifier = newNotifier("PROJ", "repo");
        Run<?, ?> run = mock(Run.class);
        Job<?, ?> job = mock(Job.class);
        BuildListener listener = mock(BuildListener.class);
        HttpNotifier httpNotifier = mock(HttpNotifier.class);
        HttpNotifierSelector selector = mock(HttpNotifierSelector.class);
        StashNotifier.DescriptorImpl globalDescriptor = mock(StashNotifier.DescriptorImpl.class);
        NotificationResult expectedResult = NotificationResult.newSuccess();

        doReturn(job).when(run).getParent();
        when(job.getFullName()).thenReturn("folder/application/branch");
        when(run.getExternalizableId()).thenReturn("folder/application/branch#1");
        when(listener.getLogger()).thenReturn(System.out);
        when(httpNotifier.send(any(), any(), any(), any())).thenReturn(expectedResult);
        when(selector.select(any())).thenReturn(httpNotifier);
        doReturn(globalDescriptor).when(notifier).getGlobalDescriptor();
        doReturn("build-key").when(notifier).getBuildKey(run, listener);
        doReturn("folder/application").when(notifier).getBuildParent(run);
        doReturn("PROJ").when(notifier).expandValue(run, listener, "PROJ");
        doReturn("repo").when(notifier).expandValue(run, listener, "repo");
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
                "https://bitbucket.example/rest/api/latest/projects/PROJ/repos/repo/commits/25a4b3c9/builds")));
        assertThat(payload.getValue().getString("parent"), is("folder/application"));
    }

    private RequiredBuildNotifier newNotifier(String projectKey, String repositorySlug) {
        try (MockedStatic<JenkinsLocationConfiguration> configuration = mockStatic(JenkinsLocationConfiguration.class)) {
            return spy(new RequiredBuildNotifier(projectKey, repositorySlug));
        }
    }
}
