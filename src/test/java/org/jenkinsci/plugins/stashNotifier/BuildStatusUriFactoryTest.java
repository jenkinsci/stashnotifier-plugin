package org.jenkinsci.plugins.stashNotifier;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

class BuildStatusUriFactoryTest {

    @Test
    void shouldCreateLegacyUriWithTrailingSlash() {
        String baseUri = "http://localhost:12345/";
        URI expected = URI.create("http://localhost:12345/rest/build-status/1.0/commits/25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        URI actual = BuildStatusUriFactory.create(baseUri, "25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        assertThat(actual, equalTo(expected));
    }

    @Test
    void shouldCreateLegacyUriWithNoTrailingSlash() {
        String baseUri = "http://localhost:12345";
        URI expected = URI.create("http://localhost:12345/rest/build-status/1.0/commits/25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        URI actual = BuildStatusUriFactory.create(baseUri, "25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        assertThat(actual, equalTo(expected));
    }

    @Test
    void shouldCreateLegacyUriWithBasePathTrailingSlash() {
        String baseUri = "http://localhost:12345/some-path/";
        URI expected = URI.create("http://localhost:12345/some-path/rest/build-status/1.0/commits/25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        URI actual = BuildStatusUriFactory.create(baseUri, "25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        assertThat(actual, equalTo(expected));
    }

    @Test
    void shouldCreateLegacyUriWithBasePathNoTrailingSlash() {
        String baseUri = "http://localhost:12345/some-path";
        URI expected = URI.create("http://localhost:12345/some-path/rest/build-status/1.0/commits/25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        URI actual = BuildStatusUriFactory.create(baseUri, "25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        assertThat(actual, equalTo(expected));
    }

    @Test
    void shouldCreateRepoScopedUri() {
        String baseUri = "http://localhost:12345";
        URI expected = URI.create("http://localhost:12345/rest/api/latest/projects/PROJ/repos/my-repo/commits/abc123/builds");
        URI actual = BuildStatusUriFactory.create(baseUri, "PROJ", "my-repo", "abc123");
        assertThat(actual, equalTo(expected));
    }

    @Test
    void shouldCreateRepoScopedUriWithTrailingSlash() {
        String baseUri = "http://localhost:12345/";
        URI expected = URI.create("http://localhost:12345/rest/api/latest/projects/PROJ/repos/my-repo/commits/abc123/builds");
        URI actual = BuildStatusUriFactory.create(baseUri, "PROJ", "my-repo", "abc123");
        assertThat(actual, equalTo(expected));
    }

    @Test
    void shouldCreateRepoScopedUriWithBasePath() {
        String baseUri = "http://localhost:12345/bitbucket";
        URI expected = URI.create("http://localhost:12345/bitbucket/rest/api/latest/projects/PROJ/repos/my-repo/commits/25a4b3c9/builds");
        URI actual = BuildStatusUriFactory.create(baseUri, "PROJ", "my-repo", "25a4b3c9");
        assertThat(actual, equalTo(expected));
    }
}
