package me.batanov.jenkins.plugins.stash.notifier;

import hudson.model.AbstractBuild;

import javax.annotation.Nonnull;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 16:09
 */
public interface DescriptionBuilder {
    @Nonnull
    String getNotificationDescription(AbstractBuild<?, ?> build);
}
