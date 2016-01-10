package me.batanov.jenkins.plugins.stash.notifier;

import hudson.model.AbstractBuild;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 20:14
 */
public interface BuildStateMapper {
    BuildStatus getBuildStatus(AbstractBuild<?, ?> build);
}
