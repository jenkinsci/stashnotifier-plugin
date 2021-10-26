package org.jenkinsci.plugins.stashNotifier;

import edu.umd.cs.findbugs.annotations.NonNull;
import net.sf.json.JSONObject;

import java.net.URI;

/**
 * Implement this interface to change the way requests are made to Bitbucket.
 */
public interface HttpNotifier {
    /**
     * Basic contract for sending Bitbucket build status notifications.
     *
     * @param uri fully-formed URI (stash-base-uri/rest/build-status/1.0/commits/commit-id)
     * @param payload body of status to post
     * @param settings user or administrator defined settings for the request
     * @param context build info
     * @return result of posting status
     */
    @NonNull
    NotificationResult send(@NonNull URI uri, @NonNull JSONObject payload, @NonNull NotificationSettings settings, @NonNull NotificationContext context);
}
