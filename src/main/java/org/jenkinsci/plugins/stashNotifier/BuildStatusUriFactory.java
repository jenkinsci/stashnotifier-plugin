package org.jenkinsci.plugins.stashNotifier;

import org.apache.commons.lang.StringUtils;

import java.net.URI;

public class BuildStatusUriFactory {
    private BuildStatusUriFactory() {
    }

    public static URI create(String baseUri, String commit) {
        String tidyBase = StringUtils.removeEnd(baseUri.toString(), "/");
        String uri = String.join("/", tidyBase, "rest/build-status/1.0/commits", commit);
        return URI.create(uri);
    }
}
