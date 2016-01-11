package me.batanov.jenkins.plugins.atlassian.bitbucket.notifier;

import hudson.model.AbstractBuild;

import javax.annotation.Nonnull;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 20:14
 */
public interface BuildStateMapper {
    @Nonnull BuildStatus getBuildStatus(AbstractBuild<?, ?> build);
}
