package org.jenkinsci.plugins.stashNotifier;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.ItemGroup;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import jenkins.branch.MultiBranchProject;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import java.io.IOException;
import java.net.URI;

/**
 * Notifies Bitbucket using the repository build status API required by the
 * Required Builds merge check.
 */
public class RequiredBuildNotifier extends StashNotifier {
    private final String bitbucketProjectKey;
    private final String repositorySlug;

    @DataBoundConstructor
    public RequiredBuildNotifier(String bitbucketProjectKey, String repositorySlug) {
        this.bitbucketProjectKey = bitbucketProjectKey;
        this.repositorySlug = repositorySlug;
    }

    public String getBitbucketProjectKey() {
        return bitbucketProjectKey;
    }

    public String getRepositorySlug() {
        return repositorySlug;
    }

    public String getBuildKey() {
        return super.getProjectKey();
    }

    @DataBoundSetter
    public void setBuildKey(String buildKey) {
        super.setProjectKey(buildKey);
    }

    @Override
    public void setProjectKey(String projectKey) {
        super.setProjectKey(projectKey);
    }

    @Override
    protected URI createBuildStatusUri(
            String stashURL,
            String commitSha1,
            Run<?, ?> run,
            TaskListener listener) {
        try {
            String expandedProjectKey = expandValue(run, listener, bitbucketProjectKey);
            String expandedRepositorySlug = expandValue(run, listener, repositorySlug);
            if (StringUtils.isBlank(expandedProjectKey)) {
                throw new IllegalArgumentException("Bitbucket project key must not be empty");
            }
            if (StringUtils.isBlank(expandedRepositorySlug)) {
                throw new IllegalArgumentException("Bitbucket repository slug must not be empty");
            }
            return BuildStatusUriFactory.createRequiredBuild(
                    stashURL,
                    expandedProjectKey,
                    expandedRepositorySlug,
                    commitSha1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalArgumentException("Unable to expand Bitbucket repository coordinates", e);
        } catch (IOException | MacroEvaluationException e) {
            throw new IllegalArgumentException("Unable to expand Bitbucket repository coordinates", e);
        }
    }

    @Override
    protected JSONObject createNotificationPayload(
            Run<?, ?> run,
            StashBuildState state,
            TaskListener listener) {
        JSONObject payload = super.createNotificationPayload(run, state, listener);
        payload.put("parent", abbreviate(getBuildParent(run), MAX_FIELD_LENGTH));
        return payload;
    }

    String getBuildParent(Run<?, ?> run) {
        ItemGroup<?> parent = run.getParent().getParent();
        if (parent instanceof MultiBranchProject<?, ?>) {
            return parent.getFullName();
        }
        return run.getParent().getFullName();
    }

    @Symbol("notifyBitbucketRequiredBuild")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {
        @SuppressWarnings("rawtypes")
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Notify Bitbucket Required Build";
        }

        @Override
        public String getGlobalConfigPage() {
            return null;
        }
    }
}
