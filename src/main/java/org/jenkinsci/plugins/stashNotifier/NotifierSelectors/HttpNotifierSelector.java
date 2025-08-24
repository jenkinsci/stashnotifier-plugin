package org.jenkinsci.plugins.stashNotifier.NotifierSelectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Run;
import hudson.model.TaskListener;
import org.jenkinsci.plugins.stashNotifier.Notifiers.HttpNotifier;
import org.jenkinsci.plugins.stashNotifier.SelectionContext;
import org.jenkinsci.plugins.stashNotifier.StashNotifier;

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
     * @param context parameters useful for selecting a notifier
     * @return selected notifier
     * @see StashNotifier#prebuild(AbstractBuild, BuildListener)
     * @see StashNotifier#perform(Run, FilePath, Launcher, TaskListener)
     */
    HttpNotifier select(@NonNull SelectionContext context);
}
