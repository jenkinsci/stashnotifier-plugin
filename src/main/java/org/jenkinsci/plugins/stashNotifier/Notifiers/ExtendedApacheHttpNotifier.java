package org.jenkinsci.plugins.stashNotifier.Notifiers;

import net.sf.json.JSONObject;
import org.jenkinsci.plugins.stashNotifier.BuildInformation;
import org.jenkinsci.plugins.stashNotifier.NotificationContext;

public class ExtendedApacheHttpNotifier extends DefaultApacheHttpNotifier {
    /**
     * Returns the HTTP POST entity body with the JSON representation of the
     * run result to be sent to the Bitbucket build API.
     *
     * @param context the NotificationContext for the current build
     * @return JSON body for POST to Bitbucket build API
     */
    @Override
    public JSONObject createNotificationPayload(NotificationContext context) {

        BuildInformation information = context.getBuildInformation();
        String buildId = abbreviate(information.getBuildKey(), MAX_FIELD_LENGTH);

        JSONObject json = super.createNotificationPayload(context);

        json.put("parent", buildId);
        json.put("buildNumber", information.getRunId());
        json.put("duration", information.getRunDuration());

        return json;
    }
}
