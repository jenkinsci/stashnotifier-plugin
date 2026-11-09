package org.jenkinsci.plugins.stashNotifier;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import hudson.model.Result;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlSelect;
import org.htmlunit.html.HtmlTextInput;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.noContent;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

@WithJenkins
@WireMockTest
class BitbucketNotifierPipelineIT {

    @Test
    void notifyBitbucketUsesLegacyApiFromGlobalConfiguration(
            JenkinsRule jenkins, WireMockRuntimeInfo bitbucketServer) throws Exception {
        WireMock bitbucket = prepareBitbucket(bitbucketServer);
        saveGlobalConfiguration(
                jenkins,
                bitbucketServer.getHttpBaseUrl() + "/configured",
                false);

        runPipeline(jenkins, "notify-bitbucket", """
                notifyBitbucket(commitSha1: '2222222222222222')
                """);

        verifySinglePost(bitbucket, "/configured/rest/build-status/1.0/commits/2222222222222222");
    }

    @Test
    void notifyBitbucketUsesBuildsApiFromGlobalConfiguration(
            JenkinsRule jenkins, WireMockRuntimeInfo bitbucketServer) throws Exception {
        WireMock bitbucket = prepareBitbucket(bitbucketServer);
        saveGlobalConfiguration(
                jenkins,
                bitbucketServer.getHttpBaseUrl() + "/configured",
                true);

        runPipeline(jenkins, "notify-bitbucket-builds-api", """
                notifyBitbucket(
                    bitbucketProjectKey: 'PROJECT',
                    repositorySlug: 'repository',
                    commitSha1: '1111111111111111')
                """);

        verifySinglePost(
                bitbucket,
                "/configured/rest/api/latest/projects/PROJECT/repos/repository/commits/1111111111111111/builds");
    }

    @Test
    void notifyBitbucketCanOverrideGlobalApiSelection(
            JenkinsRule jenkins, WireMockRuntimeInfo bitbucketServer) throws Exception {
        WireMock bitbucket = prepareBitbucket(bitbucketServer);
        saveGlobalConfiguration(
                jenkins,
                bitbucketServer.getHttpBaseUrl() + "/configured",
                true);

        runPipeline(jenkins, "notify-bitbucket-api-override", """
                notifyBitbucket(
                    useBuildsApi: false,
                    commitSha1: '3333333333333333')
                """);

        verifySinglePost(bitbucket, "/configured/rest/build-status/1.0/commits/3333333333333333");
    }

    @Test
    void notifyBitbucketCanEnableBuildsApiLocally(
            JenkinsRule jenkins, WireMockRuntimeInfo bitbucketServer) throws Exception {
        WireMock bitbucket = prepareBitbucket(bitbucketServer);
        saveGlobalConfiguration(
                jenkins,
                bitbucketServer.getHttpBaseUrl() + "/configured",
                false);

        runPipeline(jenkins, "notify-bitbucket-builds-api-override", """
                notifyBitbucket(
                    useBuildsApi: true,
                    bitbucketProjectKey: 'PROJECT',
                    repositorySlug: 'repository',
                    commitSha1: '5555555555555555')
                """);

        verifySinglePost(
                bitbucket,
                "/configured/rest/api/latest/projects/PROJECT/repos/repository/commits/5555555555555555/builds");
    }

    @Test
    void buildsApiRequiresRepositoryCoordinates(
            JenkinsRule jenkins, WireMockRuntimeInfo bitbucketServer) throws Exception {
        WireMock bitbucket = prepareBitbucket(bitbucketServer);
        saveGlobalConfiguration(
                jenkins,
                bitbucketServer.getHttpBaseUrl() + "/configured",
                true);

        WorkflowRun build = schedulePipeline(jenkins, "notify-bitbucket-missing-coordinates", """
                notifyBitbucket(commitSha1: '4444444444444444')
                """);

        jenkins.assertBuildStatus(Result.FAILURE, build);
        bitbucket.verifyThat(0, postRequestedFor(anyUrl()));
    }

    private static WireMock prepareBitbucket(WireMockRuntimeInfo bitbucketServer) {
        WireMock bitbucket = bitbucketServer.getWireMock();
        bitbucket.register(post(anyUrl()).willReturn(noContent()));
        return bitbucket;
    }

    private static void saveGlobalConfiguration(
            JenkinsRule jenkins,
            String bitbucketUrl,
            boolean defaultUseBuildsApi) throws Exception {
        HtmlPage page = jenkins.createWebClient().goTo("configure");
        HtmlForm form = page.getFormByName("config");
        HtmlTextInput serverUrl = form.getInputByName("_.stashRootUrl");
        serverUrl.setValue(bitbucketUrl);
        HtmlSelect api = form.getSelectByName("_.defaultUseBuildsApi");
        api.setSelectedAttribute(Boolean.toString(defaultUseBuildsApi), true);
        jenkins.submit(form);
    }

    private static void runPipeline(JenkinsRule jenkins, String name, String step) throws Exception {
        jenkins.assertBuildStatusSuccess(schedulePipeline(jenkins, name, step));
    }

    private static WorkflowRun schedulePipeline(JenkinsRule jenkins, String name, String step) throws Exception {
        WorkflowJob job = jenkins.createProject(WorkflowJob.class, name);
        job.setDefinition(new CpsFlowDefinition("node {\n" + step + "\n}", true));
        return job.scheduleBuild2(0).get();
    }

    private static void verifySinglePost(WireMock bitbucket, String path) {
        bitbucket.verifyThat(1, postRequestedFor(urlEqualTo(path)));
        bitbucket.verifyThat(1, postRequestedFor(anyUrl()));
    }
}
