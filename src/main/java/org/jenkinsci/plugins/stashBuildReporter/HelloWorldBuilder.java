package org.jenkinsci.plugins.stashBuildReporter;
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
 * Sample {@link Builder}.
 *
 * <p>
 * When the user configures the project and enables this builder,
 * {@link DescriptorImpl#newInstance(StaplerRequest)} is invoked
 * and a new {@link HelloWorldBuilder} is created. The created
 * instance is persisted to the project configuration XML by using
 * XStream, so this allows you to use instance fields (like {@link #name})
 * to remember the configuration.
 *
 * <p>
 * When a build is performed, the {@link #perform(AbstractBuild, Launcher, BuildListener)}
 * method will be invoked. 
 *
 * @author Kohsuke Kawaguchi
 */
public class HelloWorldBuilder extends Builder {

	private final String stashServerBaseUrl;
	private final String stashUserName;
	private final String stashUserPassword;

	// Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
	@DataBoundConstructor
		public HelloWorldBuilder(
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

	@Override
		public boolean perform(
				AbstractBuild build, 
				Launcher launcher, 
				BuildListener listener) {
		
			listener.getLogger().println("BaseURL: " + stashServerBaseUrl);
		
			if (Jenkins.getInstance().getRootUrl() == null) {
				listener.getLogger().println("Cannot notify Stash! (Jenkins Root URL not configured)");
				return true;
			}
		
			listener.getLogger().println("-> Stash: " + build.getDisplayName() + " nb:" + build.getNumber());
			HttpClient client = new DefaultHttpClient();
			try {
				for (Object item: build.getChangeSet().getItems()) {
					if (item instanceof GitChangeSet) {
						listener.getLogger().println("-> Change: " + ((GitChangeSet) item).getCommitId()
								+ " by " + ((GitChangeSet) item).getAuthorName());
						
						notifyStash(client, build, listener, (GitChangeSet) item);
					} else {
						listener.getLogger().println("-> Change: not a git changeset!");
					}
				}
			} catch (Exception e) {
				listener.getLogger().println("Caught exception while notifying Stash: " + e.getMessage());
			} finally {
				client.getConnectionManager().shutdown();
			}
		return true;
	}
	
	private void notifyStash(
			HttpClient client, 
			AbstractBuild build, 
			BuildListener listener, 
			GitChangeSet changeSet) throws Exception {
		
		HttpResponse res = null;
		// HttpPost req = new HttpPost("http://si-nvoll.si.de.bosch.com:7990/rest/build-status/1.0/commits/" + changeSet.getCommitId());
		HttpPost req = new HttpPost(stashServerBaseUrl + "/" + "/rest/build-status/1.0/commits/" + changeSet.getCommitId());
		req.addHeader(BasicScheme.authenticate(new UsernamePasswordCredentials(stashUserName, stashUserPassword), "UTF-8", false));
		req.addHeader("Content-type", "application/json");
		
		
		StringBuilder builder = new StringBuilder();
		builder.append("{\"state\":\"");
		
		listener.getLogger().println("Build result: " + build.getResult());
		if ((build.getResult() == null) 
				|| (!build.getResult().equals(Result.SUCCESS))) {
			builder.append("FAILED");
		} else {
			builder.append("SUCCESSFUL");
		}
		
		listener.getLogger().println("got this far: " + builder.toString());
		
		builder.append("\", \"key\":\"");
		builder.append(build.getFullDisplayName());
		
		listener.getLogger().println("got this far: " + builder.toString());
		
		builder.append("\", \"description\":\"built by Jenkins @ ");
		builder.append(Jenkins.getInstance().getRootUrl());
		
		listener.getLogger().println("got this far: " + builder.toString());
		
		builder.append("\", \"url\":\"");
		builder.append(Jenkins.getInstance().getRootUrl());
		builder.append(build.getUrl());
		
		listener.getLogger().println("got this far: " + builder.toString());
		
		builder.append("\"}");
		req.setEntity(new StringEntity(builder.toString()));
		
		listener.getLogger().println("got this far: " + builder.toString());
		
		res = client.execute(req);
		if (res.getStatusLine().getStatusCode() != 204) {
			listener.getLogger().println(
					"Stash notification failed for commit "
							+ changeSet.getCommitId() 
							+ " (" + changeSet.getComment() + ")");				
			
			HttpEntity resEntity = res.getEntity();
			listener.getLogger().println(EntityUtils.toString(resEntity));
		} else {
			listener.getLogger().println(
					"Successfully notified Stash for commit " 
							+ changeSet.getCommitId() 
							+ " (" + changeSet.getComment() + ")");
		}
	}

// Overridden for better type safety.
// If your plugin doesn't really define any property on Descriptor,
// you don't have to do this.
@Override
public DescriptorImpl getDescriptor() {
	return (DescriptorImpl)super.getDescriptor();
}

/**
 * Descriptor for {@link HelloWorldBuilder}. Used as a singleton.
 * The class is marked as public so that it can be accessed from views.
 *
 * <p>
 * See <tt>src/main/resources/hudson/plugins/hello_world/HelloWorldBuilder/*.jelly</tt>
 * for the actual HTML fragment for the configuration screen.
 */
@Extension // This indicates to Jenkins that this is an implementation of an extension point.
public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
	/**
	 * To persist global configuration information,
	 * simply store it in a field and call save().
	 *
	 * <p>
	 * If you don't want fields to be persisted, use <tt>transient</tt>.
	 */
	private boolean useFrench;

	public FormValidation doCheckStashServerBaseUrl(@QueryParameter String value) 
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
	
	public FormValidation doCheckStashUserPassword(@QueryParameter String value) 
		throws IOException, ServletException {
		
		if (value.trim().equals("")) {
			return FormValidation.warning("You should use a non-empty password!");
		} else {
			return FormValidation.ok();
		}
	}
	
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
		
			// To persist global configuration information,
			// set that to properties and call save().
			useFrench = formData.getBoolean("useFrench");
			// ^Can also use req.bindJSON(this, formData);
			//  (easier when there are many fields; need set* methods for this, like setUseFrench)
			save();
			return super.configure(req,formData);
		}

	/**
	 * This method returns true if the global configuration says we should speak French.
	 *
	 * The method name is bit awkward because global.jelly calls this method to determine
	 * the initial state of the checkbox by the naming convention.
	 */
	public boolean getUseFrench() {
		return useFrench;
	}
}
}

