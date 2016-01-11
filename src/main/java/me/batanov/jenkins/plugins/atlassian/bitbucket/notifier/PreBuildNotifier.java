package me.batanov.jenkins.plugins.atlassian.bitbucket.notifier;

import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.tasks.BuildWrapper;

import java.io.IOException;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 16:28
 */
public class PreBuildNotifier extends BuildWrapper {
    @Override
    public void preCheckout(AbstractBuild build, Launcher launcher, BuildListener listener) throws IOException, InterruptedException {
        super.preCheckout(build, launcher, listener);
    }


}
