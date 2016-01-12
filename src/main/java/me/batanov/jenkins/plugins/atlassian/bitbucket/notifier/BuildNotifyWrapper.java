package me.batanov.jenkins.plugins.atlassian.bitbucket.notifier;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.tasks.BuildWrapper;
import hudson.tasks.BuildWrapperDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.IOException;
import java.io.PrintStream;
import java.util.List;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         11.01.2016 16:48
 */
public final class BuildNotifyWrapper extends BuildWrapper {

    //https://github.com/jenkinsci/coverity-plugin/tree/master/src/main/java/jenkins/plugins/coverity
    //https://github.com/jenkinsci/coverity-plugin/blob/master/src/main/resources/jenkins/plugins/coverity/CoverityPublisher/global.jelly

    @DataBoundConstructor
    public BuildNotifyWrapper(boolean preNotify, List<NotifiedServer> servers) {
    }

    @Override
    public BuildWrapper.Environment setUp(final AbstractBuild build, final Launcher launcher, final BuildListener listener) throws IOException, InterruptedException {
        final PrintStream logger = listener.getLogger();

        logger.println("Pre build (setUp) notifier triggered");

        return new BuildWrapper.Environment() {
            @Override
            public boolean tearDown(AbstractBuild build, BuildListener listener) throws IOException, InterruptedException {

                logger.println("Post build (setUp) notifier triggered");

                return true;
            }
        };
    }

    @Override
    public Descriptor getDescriptor() {
        return (Descriptor) super.getDescriptor();
    }

    @Extension
    public static class Descriptor extends BuildWrapperDescriptor {

        @Override
        public boolean isApplicable(final AbstractProject<?, ?> item) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Notify stash instance";
        }
    }
}
