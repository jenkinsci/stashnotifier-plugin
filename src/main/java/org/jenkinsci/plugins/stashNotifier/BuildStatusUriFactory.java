package org.jenkinsci.plugins.stashNotifier;

import org.apache.commons.lang.StringUtils;

import java.net.URI;

public class BuildStatusUriFactory {
    private BuildStatusUriFactory() {
    }

    public static URI create(String baseUri, String commit) {
        String tidyBase = StringUtils.removeEnd(baseUri, "/");
        String uri = String.join("/", tidyBase, "rest/build-status/1.0/commits", commit);
        return URI.create(uri);
    }

    public static URI create(String baseUri, String projectKey, String repoSlug, String commit) {
        String tidyBase = StringUtils.removeEnd(baseUri, "/");
        String uri = String.join("/", tidyBase, "rest/api/latest/projects", projectKey, "repos", repoSlug, "commits", commit, "builds");
        return URI.create(uri);
    }
}
