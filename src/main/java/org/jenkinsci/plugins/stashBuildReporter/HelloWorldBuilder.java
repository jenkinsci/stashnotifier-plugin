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
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import javax.servlet.jsp.jstl.sql.ResultSupport;

import java.io.IOException;

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

	private final String name;

	// Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
	@DataBoundConstructor
		public HelloWorldBuilder(String name) {
			this.name = name;
		}

	/**
	 * We'll use this from the <tt>config.jelly</tt>.
	 */
	public String getName() {
		return name;
	}

	@Override
		public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener) {
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
		HttpPost req = new HttpPost("http://si-nvoll.si.de.bosch.com:7990/rest/build-status/1.0/commits/" + changeSet.getCommitId());
		req.addHeader(BasicScheme.authenticate(new UsernamePasswordCredentials("jenkins", "bios-rules5"), "UTF-8", false));
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

	/**
	 * Performs on-the-fly validation of the form field 'name'.
	 *
	 * @param value
	 *      This parameter receives the value that the user has typed.
	 * @return
	 *      Indicates the outcome of the validation. This is sent to the browser.
	 */
	public FormValidation doCheckName(@QueryParameter String value)
		throws IOException, ServletException {
			if (value.length() == 0)
				return FormValidation.error("Please set a name");
			if (value.length() < 4)
				return FormValidation.warning("Isn't the name too short?");
			return FormValidation.ok();
		}

	public boolean isApplicable(Class<? extends AbstractProject> aClass) {
		// Indicates that this builder can be used with all kinds of project types 
		return true;
	}

	/**
	 * This human readable name is used in the configuration screen.
	 */
	public String getDisplayName() {
		return "Say hello world";
	}

	@Override
		public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
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

