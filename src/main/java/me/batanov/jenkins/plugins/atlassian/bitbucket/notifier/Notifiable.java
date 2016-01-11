package me.batanov.jenkins.plugins.atlassian.bitbucket.notifier;

import com.sun.istack.internal.NotNull;
import hudson.model.AbstractBuild;
import me.batanov.jenkins.plugins.atlassian.bitbucket.notifier.exception.NotificationFailedException;

import java.util.List;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 15:47
 */
public interface Notifiable {
    void Notify(@NotNull AbstractBuild<?, ?> build, List<String> commits) throws NotificationFailedException;
}
