package me.batanov.jenkins.plugins.stash.notifier;

import hudson.model.AbstractBuild;

import javax.annotation.Nonnull;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 16:10
 */
public class DefaultDescriptionBuilder implements DescriptionBuilder {
    @Nonnull
    public String getNotificationDescription(AbstractBuild<?, ?> build) {
        return build.getDescription();
    }
}
