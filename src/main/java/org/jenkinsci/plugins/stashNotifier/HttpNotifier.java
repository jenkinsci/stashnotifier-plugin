package org.jenkinsci.plugins.stashNotifier;

import net.sf.json.JSONObject;

import java.net.URI;

public interface HttpNotifier {
    NotificationResult send(URI uri, JSONObject payload, NotificationSettings settings, NotificationContext context);
}
