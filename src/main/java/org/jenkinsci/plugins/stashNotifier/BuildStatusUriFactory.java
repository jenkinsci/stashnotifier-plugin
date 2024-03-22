package org.jenkinsci.plugins.stashNotifier;

import org.apache.commons.lang.StringUtils;

import java.net.URI;

public class BuildStatusUriFactory {
    private BuildStatusUriFactory() {
    }

    public static URI create(String baseUri, String projectKey, String slug, String commit) {
        String tidyBase = StringUtils.removeEnd(baseUri, "/");

        String uri;
        if(projectKey == null || slug == null || projectKey.isEmpty() || slug.isEmpty()) {
            uri = String.join("/", tidyBase, "rest/build-status/1.0/commits", commit);
        }
        else {
            uri = String.join("/", tidyBase, "rest/api/latest/projects", projectKey, "repos", slug, "commits", commit, "builds");
        }
        return URI.create(uri);
    }
}
