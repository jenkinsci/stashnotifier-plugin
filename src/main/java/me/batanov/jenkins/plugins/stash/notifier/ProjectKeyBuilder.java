package me.batanov.jenkins.plugins.stash.notifier;

import hudson.model.AbstractBuild;

import javax.annotation.Nonnull;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 16:02
 */
public interface ProjectKeyBuilder {
    @Nonnull
    String getNotificationKey(AbstractBuild<?, ?> build);
}
