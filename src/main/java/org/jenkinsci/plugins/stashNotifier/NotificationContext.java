package org.jenkinsci.plugins.stashNotifier;

import java.io.PrintStream;

public class NotificationContext {
    private final PrintStream logger;
    private final String runId;

    public NotificationContext(PrintStream logger, String runId) {
        this.logger = logger;
        this.runId = runId;
    }

    public PrintStream getLogger() {
        return logger;
    }

    public String getRunId() {
        return runId;
    }
}
