package org.jenkinsci.plugins.stashNotifier;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Run;
import hudson.model.TaskListener;

/**
 * Implement this interface to have more control over which {@link HttpNotifier}
 * will be used at runtime.
 *
 * @see DefaultHttpNotifierSelector
 */
public interface HttpNotifierSelector {

    /**
     * Invoked once per Bitbucket notification. {@link SelectionContext} makes
     * this method useful for performing migrations on a running system without
     * restarts.
     *
     * @see StashNotifier#prebuild(AbstractBuild, BuildListener)
     * @see StashNotifier#perform(Run, FilePath, Launcher, TaskListener)
     * @param context parameters useful for selecting a notifier
     * @return selected notifier
     */
    @NonNull HttpNotifier select(@NonNull SelectionContext context);
}
