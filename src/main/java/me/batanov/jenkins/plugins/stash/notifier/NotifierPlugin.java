package me.batanov.jenkins.plugins.stash.notifier;

import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.BuildStepListener;
import hudson.tasks.BuildStep;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 16:28
 */
public class NotifierPlugin extends BuildStepListener {

    @Override
    public void started(AbstractBuild abstractBuild, BuildStep buildStep, BuildListener buildListener) {
        
    }

    @Override
    public void finished(AbstractBuild abstractBuild, BuildStep buildStep, BuildListener buildListener, boolean b) {

    }
}
