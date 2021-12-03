package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;

/**
 * Properties defined by a user or administrator about how they want the
 * notification to be sent.
 */
public class NotificationSettings {
    private final boolean ignoreUnverifiedSSL;
    private final boolean tokenCredentials;
    private final UsernamePasswordCredentials credentials;

    public NotificationSettings(boolean ignoreUnverifiedSSL, boolean tokenCredentials, UsernamePasswordCredentials credentials) {
        this.ignoreUnverifiedSSL = ignoreUnverifiedSSL;
        this.tokenCredentials = tokenCredentials;
        this.credentials = credentials;
    }

    public boolean isIgnoreUnverifiedSSL() {
        return ignoreUnverifiedSSL;
    }

    public boolean isTokenCredentials(){
        return tokenCredentials;
    }
    
    @CheckForNull
    public UsernamePasswordCredentials getCredentials() {
        return credentials;
    }
}
