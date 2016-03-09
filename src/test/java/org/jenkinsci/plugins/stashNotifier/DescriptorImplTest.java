package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kohsuke.stapler.StaplerRequest;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * Created by Vlad Medvedev on 27.01.2016.
 * vladislav.medvedev@devfactory.com
 */

@RunWith(PowerMockRunner.class)
@PrepareForTest({StashNotifier.DescriptorImpl.class, CredentialsProvider.class, Jenkins.class})
public class DescriptorImplTest {

    /** Class under test. */
    private StashNotifier.DescriptorImpl desc;

    private JSONObject json;
    private Hudson jenkins;

    @Before
    public void setUp() throws Exception {
        jenkins = PowerMockito.mock(Hudson.class);

        PowerMockito.mockStatic(Jenkins.class);
        when(Jenkins.getInstance()).thenReturn(jenkins);

        json = new JSONObject();
        json.put("stashRootUrl", "http://stash-root-url");
        json.put("credentialsId", "someCredentialsId");
        json.put("projectKey", "someProjectKey");
        json.put("ignoreUnverifiedSsl", "true");
        json.put("includeBuildNumberInKey", "true");
        json.put("prependParentProjectKey", "true");
        json.put("disableInprogressNotification", "true");

        desc = spy(new StashNotifier.DescriptorImpl(false));
    }

    @Test
    public void testConfigure() throws Descriptor.FormException {
        //given
        doNothing().when(desc).save();

        //when
        desc.configure(mock(StaplerRequest.class), json);

        //then
        assertThat(desc.getStashRootUrl(), is("http://stash-root-url"));
        assertThat(desc.getCredentialsId(), is("someCredentialsId"));
        assertThat(desc.getProjectKey(), is("someProjectKey"));
        assertThat(desc.getDisplayName(), is("Notify Stash Instance"));
        assertThat(desc.isDisableInprogressNotification(), is(true));
        assertThat(desc.isIgnoreUnverifiedSsl(), is(true));
        assertThat(desc.isIncludeBuildNumberInKey(), is(true));
        assertThat(desc.isPrependParentProjectKey(), is(true));
        assertThat(desc.isApplicable(AbstractProject.class), is(true));
    }

    @Test
    public void test_doFillCredentialsIdItems_project_null() {
        when(jenkins.hasPermission(Item.CONFIGURE)).thenReturn(false);

        ListBoxModel listBoxModel = desc.doFillCredentialsIdItems(null);

        assertThat(listBoxModel, is(not(nullValue())));
    }

    @Test
    public void test_doFillCredentialsIdItems_no_permission() {
        Item project = mock(Item.class);
        when(project.hasPermission(eq(Item.CONFIGURE))).thenReturn(false);
        when(jenkins.hasPermission(Item.CONFIGURE)).thenReturn(false);

        ListBoxModel listBoxModel = desc.doFillCredentialsIdItems(project);
        assertThat(listBoxModel, is(not(nullValue())));
    }

    @Test
    public void test_doFillCredentialsIdItems_has_permission() {
        //given
        Item project = mock(Item.class);
        when(project.hasPermission(eq(Item.CONFIGURE))).thenReturn(true);
        PowerMockito.mockStatic(CredentialsProvider.class);
        PowerMockito.when(CredentialsProvider.lookupCredentials(
                Mockito.<Class>anyObject(),
                Mockito.<Item>anyObject(),
                Mockito.<Authentication>anyObject(),
                Mockito.<ArrayList<DomainRequirement>>anyObject())).thenReturn(new ArrayList());

        //when
        ListBoxModel listBoxModel = desc.doFillCredentialsIdItems(project);

        //then
        assertThat(listBoxModel, is(not(nullValue())));
    }

    private FormValidation doCheckStashServerBaseUrl(String url) throws IOException, ServletException {
        //given
        Item project = mock(Item.class);
        when(project.hasPermission(eq(Item.CONFIGURE))).thenReturn(true);
        PowerMockito.mockStatic(CredentialsProvider.class);
        PowerMockito.when(CredentialsProvider.lookupCredentials(
                Mockito.<Class>anyObject(),
                Mockito.<Item>anyObject(),
                Mockito.<Authentication>anyObject(),
                Mockito.<List<DomainRequirement>>anyObject())).thenReturn(new ArrayList());

        return desc.doCheckStashServerBaseUrl(url);
    }

    @Test
    public void test_doCheckStashServerBaseUrl_empty() throws IOException, ServletException {
        FormValidation listBoxModel = doCheckStashServerBaseUrl("");
        assertThat(listBoxModel.kind, is(FormValidation.Kind.ERROR));
    }

    @Test
    public void test_doCheckStashServerBaseUrl() throws IOException, ServletException {
        FormValidation listBoxModel = doCheckStashServerBaseUrl("http://some-stash-url");
        assertThat(listBoxModel.kind, is(FormValidation.Kind.OK));
    }
}