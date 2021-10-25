package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;

/**
 * Properties defined by a user or administrator about how they want the
 * notification to be sent.
 */
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

    @CheckForNull
    public UsernamePasswordCredentials getCredentials() {
        return credentials;
    }
}
