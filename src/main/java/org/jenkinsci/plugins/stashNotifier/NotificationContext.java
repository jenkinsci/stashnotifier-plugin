package org.jenkinsci.plugins.stashNotifier;

import hudson.model.Run;

import java.io.PrintStream;

/**
 * Properties from the build where this is running.
 */
public class NotificationContext {
    private final PrintStream logger;
    private final String runId;

    public NotificationContext(PrintStream logger, String runId) {
        this.logger = logger;
        this.runId = runId;
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
}
