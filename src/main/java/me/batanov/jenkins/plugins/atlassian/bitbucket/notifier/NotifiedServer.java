package me.batanov.jenkins.plugins.atlassian.bitbucket.notifier;

import org.kohsuke.stapler.DataBoundConstructor;

import java.util.List;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-12 21:39
 */
public class NotifiedServer {
    private String id;

    private List<String> commits;

    @DataBoundConstructor
    public NotifiedServer(String id, List<String> commits) {
        this.id = id;
        this.commits = commits;
    }
}
