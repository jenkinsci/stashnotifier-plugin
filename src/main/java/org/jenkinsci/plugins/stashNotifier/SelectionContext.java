package org.jenkinsci.plugins.stashNotifier;

import hudson.model.AbstractItem;
import org.jenkinsci.plugins.stashNotifier.NotifierSelectors.HttpNotifierSelector;
import org.jenkinsci.plugins.stashNotifier.Notifiers.HttpNotifier;

import java.util.Objects;
import java.util.StringJoiner;

/**
 * Properties for selecting a {@link HttpNotifier}.
 *
 * @see HttpNotifierSelector#select(SelectionContext)
 */
public class SelectionContext {
    private final String jobFullName;
    private final String bitBucketProjectKey;
    private final String bitBucketProjectSlug;

    public SelectionContext(String jobFullName, String projectKey, String projectSlug) {
        this.jobFullName = jobFullName;
        this.bitBucketProjectKey = projectKey;
        this.bitBucketProjectSlug = projectSlug;
    }

    /**
     * The {@link AbstractItem#getFullName()} of the running job.
     *
     * @return job's full name
     */
    public String getJobFullName() {
        return jobFullName;
    }

    public String getBitBucketProjectKey() {
        return bitBucketProjectKey;
    }

    public String getBitBucketProjectSlug() {
        return bitBucketProjectSlug;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SelectionContext that = (SelectionContext) o;
        return Objects.equals(jobFullName, that.jobFullName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(jobFullName);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", SelectionContext.class.getSimpleName() + "[", "]")
                .add("jobFullName='" + jobFullName + "'")
                .toString();
    }
}
