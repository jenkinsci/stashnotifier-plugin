package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.common.CertificateCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;

import org.jenkinsci.plugins.plaincredentials.StringCredentials;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A very simple matcher to ensure we only show username/password or certificate credentials
 */
public class StashCredentialMatcher implements CredentialsMatcher {
    public boolean matches(@NonNull Credentials credentials) {
        return (credentials instanceof CertificateCredentials) || (credentials instanceof UsernamePasswordCredentials || (credentials instanceof StringCredentials));
    }
}
