package org.jenkinsci.plugins.stashNotifier;

import hudson.model.Run;

import java.io.PrintStream;

/**
 * Properties from the build where this is running.
 */
public class NotificationContext {
    private final PrintStream logger;
    private final String runId;
    private final BuildInformation buildInformation;

    public NotificationContext(PrintStream logger, String runId, BuildInformation buildInformation) {
        this.logger = logger;
        this.runId = runId;
        this.buildInformation = buildInformation;
    }

    /**
     * Anything logged here will show up in the running build's console log.
     *
     * @return handle to build's log
     */
    public PrintStream getLogger() {
        return logger;
    }

    /**
     * This is the {@link Run#getExternalizableId()} from the running build,
     * useful for detailed server-side logging (such as through slf4j).
     *
     * @return build's id
     */
    public String getRunId() {
        return runId;
    }

    public BuildInformation getBuildInformation() { return buildInformation; }
}
