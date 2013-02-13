package org.jenkinsci.plugins.stashNotifier;

import hudson.Launcher;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.AbstractProject;
import hudson.model.Result;
import hudson.plugins.git.GitChangeSet;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import net.sf.json.JSONObject;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;

import java.io.IOException;
import java.net.URL;

import jenkins.model.Jenkins;

/**
 * Notifies a configured <a href="http://www.atlassian.com/software/stash/overview">Atlassian Stash</a> instance of build results through
 * the Atlassian <a href="https://developer.atlassian.com/static/rest/stash/latest/stash-build-integration-rest.html">Stash Build REST API</a>. 
 * 
 * Only basic authentication is supported at the moment.
 * 
 * @author	Georg Gruetter
 */
public class Notifier extends Builder {
	
	// attributes --------------------------------------------------------------

	private final String stashServerBaseUrl;
	private final String stashUserName;
	private final String stashUserPassword;
	
	// public members ----------------------------------------------------------

	@DataBoundConstructor
	public Notifier(
			String stashServerBaseUrl,
			String stashUserName,
			String stashUserPassword) {
		this.stashServerBaseUrl = stashServerBaseUrl;
		this.stashUserName = stashUserName;
		this.stashUserPassword = stashUserPassword;
	}

	public String getStashServerBaseUrl() {
		return stashServerBaseUrl;
	}

	public String getStashUserName() {
		return stashUserName;
	}

	public String getStashUserPassword() {
		return stashUserPassword;
	}

	@SuppressWarnings("rawtypes")
	@Override
	public boolean perform(
			AbstractBuild build, 
			Launcher launcher, 
			BuildListener listener) {

		if (Jenkins.getInstance().getRootUrl() == null) {
			listener.getLogger().println(
					"Cannot notify Stash! (Jenkins Root URL not configured)");
			return true;
		}

		HttpClient client = new DefaultHttpClient();
		try {
			for (Object item: build.getChangeSet().getItems()) {
				if (item instanceof GitChangeSet) {
					notifyStash(client, build, listener, (GitChangeSet) item);
				} else {
					listener.getLogger().println(
							"-> Change: not a git changeset!");
				}
			}
		} catch (Exception e) {
			listener.getLogger().println(
					"Caught exception while notifying Stash: " + e.getMessage());
		} finally {
			client.getConnectionManager().shutdown();
		}
		return true;
	}


	@Extension 
	public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

		public FormValidation doCheckStashServerBaseUrl(
					@QueryParameter String value) 
				throws IOException, ServletException {

			try {
				new URL(value);
				return FormValidation.ok();
			} catch (Exception e) {
				return FormValidation.error("Please specify a valid URL!");
			}
		}

		public FormValidation doCheckStashUserName(@QueryParameter String value)
				throws IOException, ServletException {

			if (value.trim().equals("")) {
				return FormValidation.error("Please specify a user name!");
			} else {
				return FormValidation.ok();
			}
		}

		public FormValidation doCheckStashUserPassword(
					@QueryParameter String value) 
				throws IOException, ServletException {

			if (value.trim().equals("")) {
				return FormValidation.warning(
						"You should use a non-empty password!");
			} else {
				return FormValidation.ok();
			}
		}

		@SuppressWarnings("rawtypes")
		public boolean isApplicable(Class<? extends AbstractProject> aClass) {
			return true;
		}

		/**
		 * This human readable name is used in the configuration screen.
		 */
		public String getDisplayName() {
			return "Notify Stash Instance";
		}

		@Override
		public boolean configure(
				StaplerRequest req, 
				JSONObject formData) throws FormException {

			save();
			return super.configure(req,formData);
		}
	}
	
	// non-public members ------------------------------------------------------
	
	@SuppressWarnings("rawtypes")
	private void notifyStash(
			HttpClient client, 
			AbstractBuild build, 
			BuildListener listener, 
			GitChangeSet changeSet) throws Exception {

		HttpPost req = new HttpPost(
				stashServerBaseUrl  
				+ "/rest/build-status/1.0/commits/" 
				+ changeSet.getCommitId());
		
		req.addHeader(BasicScheme.authenticate(
				new UsernamePasswordCredentials(
						stashUserName, 
						stashUserPassword), 
				"UTF-8", 
				false));
		
		req.addHeader("Content-type", "application/json");		
		req.setEntity(newStashBuildNotificationEntity(build));

		HttpResponse res = client.execute(req);
		if (res.getStatusLine().getStatusCode() != 204) {
			listener.getLogger().println(
					"Stash notification failed for commit "
							+ changeSet.getCommitId() 
							+ " (" + changeSet.getComment() + ")");				

			HttpEntity resEntity = res.getEntity();
			listener.getLogger().println(EntityUtils.toString(resEntity));
		} else {
			listener.getLogger().println(
					"Successfully notified Stash for commit with id " 
							+ changeSet.getCommitId());
		}
	}
	
	@SuppressWarnings("rawtypes")
	private HttpEntity newStashBuildNotificationEntity(AbstractBuild build) 
			throws Exception {
		
		StringBuilder builder = new StringBuilder();
		builder.append("{\"state\":\"");

		if ((build.getResult() == null) 
				|| (!build.getResult().equals(Result.SUCCESS))) {
			builder.append("FAILED");
		} else {
			builder.append("SUCCESSFUL");
		}

		builder.append("\", \"key\":\"");
		builder.append(build.getFullDisplayName());

		builder.append("\", \"description\":\"built by Jenkins @ ");
		builder.append(Jenkins.getInstance().getRootUrl());

		builder.append("\", \"url\":\"");
		builder.append(Jenkins.getInstance().getRootUrl());
		builder.append(build.getUrl());

		builder.append("\"}");
		return new StringEntity(builder.toString());
	}

}

