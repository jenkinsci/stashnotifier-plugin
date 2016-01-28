package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kohsuke.stapler.StaplerRequest;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
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
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * Created by Vlad Medvedev on 27.01.2016.
 * vladislav.medvedev@devfactory.com
 */

@RunWith(PowerMockRunner.class)
@PrepareForTest({StashNotifier.DescriptorImpl.class, com.cloudbees.plugins.credentials.CredentialsProvider.class})
public class DescriptorImplTest {
    private JSONObject json;

    @Before
    public void setUp() {
        json = new JSONObject();
        json.put("stashRootUrl", "http://stash-root-url");
        json.put("credentialsId", "someCredentialsId");
        json.put("projectKey", "someProjectKey");
        json.put("ignoreUnverifiedSsl", "true");
        json.put("includeBuildNumberInKey", "true");
        json.put("prependParentProjectKey", "true");
        json.put("disableInprogressNotification", "true");
    }

    @Test
    public void testConfigure() throws Descriptor.FormException {
        //given
        StashNotifier.DescriptorImpl desc = spy(new StashNotifier.DescriptorImpl(false));
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
        StashNotifier.DescriptorImpl desc = spy(new StashNotifier.DescriptorImpl(false));
        ListBoxModel options = desc.doFillCredentialsIdItems(null);

        assertThat(options, is(not(nullValue())));
    }

    @Test
    public void test_doFillCredentialsIdItems_no_permission() {
        StashNotifier.DescriptorImpl desc = spy(new StashNotifier.DescriptorImpl(false));
        Item project = mock(Item.class);
        when(project.hasPermission(eq(Item.CONFIGURE))).thenReturn(false);

        ListBoxModel options = desc.doFillCredentialsIdItems(project);
        assertThat(options, is(not(nullValue())));
    }

    @Test
    public void test_doFillCredentialsIdItems_has_permission() {
        //given
        Item project = mock(Item.class);
        StashNotifier.DescriptorImpl desc = spy(new StashNotifier.DescriptorImpl(false));
        when(project.hasPermission(eq(Item.CONFIGURE))).thenReturn(true);
        PowerMockito.mockStatic(com.cloudbees.plugins.credentials.CredentialsProvider.class);
        PowerMockito.when(com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
                Mockito.<Class>anyObject(),
                Mockito.<Item>anyObject(),
                Mockito.<Authentication>anyObject(),
                Mockito.<ArrayList<DomainRequirement>>anyObject())).thenReturn(new ArrayList());

        //when
        ListBoxModel options = desc.doFillCredentialsIdItems(project);

        //then
        assertThat(options, is(not(nullValue())));
    }

    private FormValidation doCheckStashServerBaseUrl(String url) throws IOException, ServletException {
        //given
        Item project = mock(Item.class);
        StashNotifier.DescriptorImpl desc = spy(new StashNotifier.DescriptorImpl(false));
        when(project.hasPermission(eq(Item.CONFIGURE))).thenReturn(true);
        PowerMockito.mockStatic(com.cloudbees.plugins.credentials.CredentialsProvider.class);
        PowerMockito.when(com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
                Mockito.<Class>anyObject(),
                Mockito.<Item>anyObject(),
                Mockito.<Authentication>anyObject(),
                Mockito.<ArrayList<DomainRequirement>>anyObject())).thenReturn(new ArrayList());

        return desc.doCheckStashServerBaseUrl(url);
    }

    @Test
    public void test_doCheckStashServerBaseUrl_empty() throws IOException, ServletException {
        FormValidation options = doCheckStashServerBaseUrl("");
        assertThat(options.kind, is(FormValidation.Kind.ERROR));
    }

    @Test
    public void test_doCheckStashServerBaseUrl() throws IOException, ServletException {
        FormValidation options = doCheckStashServerBaseUrl("http://some-stash-url");
        assertThat(options.kind, is(FormValidation.Kind.OK));
    }
}