package org.jenkinsci.plugins.stashNotifier;

public class BuildInformation {
    private final String runId;
    private final long runDuration;
    private final StashBuildState buildState;
    private final String buildKey;
    private final String buildUrl;
    private final String buildName;
    private final String buildDescription;
    public BuildInformation(String runId, long runDuration, StashBuildState buildState, String buildKey, String buildUrl, String buildName, String buildDescription) {
        this.runId = runId;
        this.runDuration = runDuration;
        this.buildState = buildState;
        this.buildKey = buildKey;
        this.buildUrl = buildUrl;
        this.buildName = buildName;
        this.buildDescription = buildDescription;
    }

    public String getRunId() {
        return runId;
    }
    public long getRunDuration() {
        return runDuration;
    }
    public StashBuildState getBuildState() {
        return buildState;
    }
    public String getBuildKey() { return buildKey; }
    public String getBuildUrl() { return buildUrl; }
    public String getBuildName() { return buildName; }
    public String getBuildDescription() { return buildDescription; }
}
