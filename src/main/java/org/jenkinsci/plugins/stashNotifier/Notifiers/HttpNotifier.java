package org.jenkinsci.plugins.stashNotifier.Notifiers;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.jenkinsci.plugins.stashNotifier.NotificationContext;
import org.jenkinsci.plugins.stashNotifier.NotificationResult;
import org.jenkinsci.plugins.stashNotifier.NotificationSettings;

import java.net.URI;

/**
 * Implement this interface to change the way requests are made to Bitbucket.
 */
public interface HttpNotifier {
    /**
     * Basic contract for sending Bitbucket build status notifications.
     *
     * @param uri fully-formed URI (stash-base-uri/rest/build-status/1.0/commits/commit-id)
     * @param settings user or administrator defined settings for the request
     * @param context build info
     * @return result of posting status
     */
    @NonNull
    NotificationResult send(@NonNull URI uri, @NonNull NotificationSettings settings, @NonNull NotificationContext context);
}
