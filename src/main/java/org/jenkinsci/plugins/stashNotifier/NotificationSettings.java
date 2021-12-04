package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.Credentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;

/**
 * Properties defined by a user or administrator about how they want the
 * notification to be sent.
 */
public class NotificationSettings {
    private final boolean ignoreUnverifiedSSL;
    private final Credentials credentials;

    public NotificationSettings(boolean ignoreUnverifiedSSL, Credentials credentials) {
        this.ignoreUnverifiedSSL = ignoreUnverifiedSSL;
        this.credentials = credentials;
    }

    public boolean isIgnoreUnverifiedSSL() {
        return ignoreUnverifiedSSL;
    }

    @CheckForNull
    public Credentials getCredentials() {
        return credentials;
    }
}
