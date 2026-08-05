package org.jenkinsci.plugins.stashNotifier;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.utils.URIBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

public class BuildStatusUriFactory {
    private BuildStatusUriFactory() {
    }

    public static URI create(String baseUri, String commit) {
        String tidyBase = StringUtils.removeEnd(baseUri, "/");
        String uri = String.join("/", tidyBase, "rest/build-status/1.0/commits", commit);
        return URI.create(uri);
    }

    public static URI createRequiredBuild(String baseUri, String projectKey, String repositorySlug, String commit) {
        try {
            URIBuilder builder = new URIBuilder(StringUtils.removeEnd(baseUri, "/"));
            List<String> pathSegments = new ArrayList<>(builder.getPathSegments());
            pathSegments.add("rest");
            pathSegments.add("api");
            pathSegments.add("latest");
            pathSegments.add("projects");
            pathSegments.add(projectKey);
            pathSegments.add("repos");
            pathSegments.add(repositorySlug);
            pathSegments.add("commits");
            pathSegments.add(commit);
            pathSegments.add("builds");
            return builder.setPathSegments(pathSegments).build();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Unable to create Required Builds URI", e);
        }
    }
}
