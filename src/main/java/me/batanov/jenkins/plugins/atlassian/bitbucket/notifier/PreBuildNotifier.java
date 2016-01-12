package me.batanov.jenkins.plugins.atlassian.bitbucket.notifier;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.tasks.BuildWrapper;
import hudson.tasks.BuildWrapperDescriptor;
import org.apache.commons.logging.Log;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.IOException;
import java.io.PrintStream;
import java.util.logging.Logger;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 16:28
 */
public final class PreBuildNotifier extends BuildWrapper {

    @DataBoundConstructor
    public PreBuildNotifier() {
        super();
        Logger.getLogger("test").warning("test");
    }

    @Override
    public BuildWrapper.Environment setUp(final AbstractBuild build,final  Launcher launcher,final  BuildListener listener) throws IOException, InterruptedException {
        final PrintStream logger = listener.getLogger();

        logger.println("Pre build (setUp) notifier triggered");

        return new BuildWrapper.Environment() {
            /* empty implementation */
        };
    }

    @Override
    public void preCheckout(AbstractBuild build, Launcher launcher, BuildListener listener) throws IOException, InterruptedException {
        listener.getLogger().println("Pre build (preCheckout) notifier triggered");

        super.preCheckout(build, launcher, listener);
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
            return "Pre build notifier wrapper";
        }
    }
}
