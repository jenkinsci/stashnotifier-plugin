package me.batanov.jenkins.plugins.atlassian.bitbucket.notifier;

import hudson.model.AbstractBuild;
import jenkins.model.Jenkins;
import jenkins.model.JenkinsLocationConfiguration;
import me.batanov.jenkins.plugins.atlassian.bitbucket.ApiServer;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.auth.AuthenticationException;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.List;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 16:06
 */
final public class NotifiableStashServerWrapper implements Notifiable {

    public static final String REST_V10_BUILD_STATUS_METHOD = "/rest/build-status/1.0/commits/";
    private static final int FIELD_MAX_WIDTH = 255;
    private ApiServer server;
    private ProjectKeyBuilder keyBuilder;
    private BuildStateMapper stateMapper;
    private DescriptionBuilder descriptionBuilder;

    public NotifiableStashServerWrapper(
            ApiServer server,
            BuildStateMapper stateMapper,
            ProjectKeyBuilder keyBuilder,
            DescriptionBuilder descriptionBuilder
    ) {
        this.server = server;
        this.stateMapper = stateMapper;
        this.keyBuilder = keyBuilder;
        this.descriptionBuilder = descriptionBuilder;
    }

    @Nonnull
    private static String cutString(@Nonnull String text) {
        if (text.length() <= FIELD_MAX_WIDTH) {
            return text;
        }

        return text.substring(0, FIELD_MAX_WIDTH - 3) + "...";
    }

    public void Notify(AbstractBuild<?, ?> build, List<String> commits) {

        String fullDisplayName = build.getFullDisplayName();
        String fullName = sanitizeDisplayName(fullDisplayName);

        HashMap<String, Object> request = new HashMap<String, Object>();
        request.put("state", stateMapper.getBuildStatus(build).name());
        request.put("key", cutString(keyBuilder.getNotificationKey(build)));
        request.put("name", cutString(fullName));
        request.put("description", cutString(descriptionBuilder.getNotificationDescription(build)));
        request.put("description", cutString(getRootUrl().concat(build.getUrl())));

        for (String commit : commits) {
            String method = REST_V10_BUILD_STATUS_METHOD + commit;
            try {
                server.performApiCall(method, request);
            } catch (AuthenticationException exception) {
                //Todo: Logging
            }
        }
    }

    /**
     * Provide a fallback for getting the instance's root URL
     *
     * @return Root URL contained in the global config
     */
    @Nonnull
    private String getRootUrl() {
        JenkinsLocationConfiguration globalConfig = new JenkinsLocationConfiguration();
        return (Jenkins.getInstance().getRootUrl() != null) ? Jenkins.getInstance().getRootUrl() : globalConfig.getUrl();
    }

    @Nonnull
    private String sanitizeDisplayName(@Nonnull String fullDisplayName) {
        // This is to replace the odd character Jenkins injects to separate
        // nested jobs, especially when using the Cloudbees Folders plugin.
        // These characters cause Stash to throw up.
        return StringEscapeUtils.
                escapeJavaScript(fullDisplayName).
                replaceAll("\\\\u00BB", "\\/");
    }
}
