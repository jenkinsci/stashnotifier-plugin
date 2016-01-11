package me.batanov.jenkins.plugins.atlassian.bitbucket.notifier;

import hudson.model.AbstractBuild;
import hudson.model.Result;

import javax.annotation.Nonnull;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         11.01.2016 13:20
 */
public class DefaultBuildStateMapper implements BuildStateMapper {
    @Nonnull
    public BuildStatus getBuildStatus(AbstractBuild<?, ?> build) {
        if (build.getResult() == null) {
            return BuildStatus.INPROGRESS;
        }
        if (build.getResult().equals(Result.SUCCESS) || build.getResult().equals(Result.UNSTABLE)) {
            return BuildStatus.SUCCESSFUL;
        }
        if (build.getResult().equals(Result.FAILURE) || build.getResult().equals(Result.ABORTED)) {
            return BuildStatus.FAILED;
        }

        // Result.NOT_BUILT
        return BuildStatus.INPROGRESS;
    }
}
