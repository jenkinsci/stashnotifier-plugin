package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;

public class NotificationSettings {
    private final boolean ignoreUnverifiedSSL;
    private final UsernamePasswordCredentials credentials;

    public NotificationSettings(boolean ignoreUnverifiedSSL, UsernamePasswordCredentials credentials) {
        this.ignoreUnverifiedSSL = ignoreUnverifiedSSL;
        this.credentials = credentials;
    }

    public boolean isIgnoreUnverifiedSSL() {
        return ignoreUnverifiedSSL;
    }

    public UsernamePasswordCredentials getCredentials() {
        return credentials;
    }
}
