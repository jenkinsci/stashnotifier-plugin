package org.jenkinsci.plugins.stashNotifier;

/**
 * States communicated to the Stash server.
 */
public enum StashBuildState {
    SUCCESSFUL,
    FAILED,
    INPROGRESS
}
