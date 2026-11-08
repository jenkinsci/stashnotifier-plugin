package org.jenkinsci.plugins.stashNotifier;

import hudson.model.AbstractItem;

import java.util.Objects;
import java.util.StringJoiner;

/**
 * Properties for selecting a {@link HttpNotifier}.
 *
 * @see HttpNotifierSelector#select(SelectionContext)
 */
public class SelectionContext {
    private final String jobFullName;

    public SelectionContext(String jobFullName) {
        this.jobFullName = jobFullName;
    }

    /**
     * The {@link AbstractItem#getFullName()} of the running job.
     *
     * @return job's full name
     */
    public String getJobFullName() {
        return jobFullName;
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
