package org.jenkinsci.plugins.stashNotifier;

/**
 * States communicated to the Bitbucket server.
 */
public enum StashBuildState {
    SUCCESSFUL,
    FAILED,
    INPROGRESS,
}
