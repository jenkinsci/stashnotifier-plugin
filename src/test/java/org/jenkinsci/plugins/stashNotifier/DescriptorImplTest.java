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
import org.kohsuke.stapler.*;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URL;
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
@PrepareForTest({StashNotifier.DescriptorImpl.class, CredentialsProvider.class, Jenkins.class, TokenList.class})
public class DescriptorImplTest {

    /**
     * Class under test.
     */
    private StashNotifier.DescriptorImpl desc;

    private JSONObject json;
    private Hudson jenkins;

    @Before
    public void setUp() throws Exception {
        jenkins = PowerMockito.mock(Hudson.class);

        PowerMockito.mockStatic(Jenkins.class);
        when(Jenkins.getInstance()).thenReturn(jenkins);

        json = new JSONObject();
        json.put("considerUnstableAsSuccess", "true");
        json.put("credentialsId", "bitbucket-credentials");
        json.put("disableInprogressNotification", "true");
        json.put("ignoreUnverifiedSsl", "true");
        json.put("includeBuildNumberInKey", "true");
        json.put("prependParentProjectKey", "true");
        json.put("projectKey", "JEN");
        json.put("stashRootUrl", "https://my.company.intranet/bitbucket");

        desc = spy(new StashNotifier.DescriptorImpl(false));
    }

    @Test
    public void testConfigure() throws Descriptor.FormException {
        //given
        doNothing().when(desc).save();

        ServletContext servletContext = mock(ServletContext.class);
        WebApp webApp = new WebApp(servletContext);

        Stapler stapler = mock(Stapler.class);
        when(stapler.getWebApp()).thenReturn(webApp);

        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        TokenList tokenList = mock(TokenList.class);

        RequestImpl staplerRequest = new RequestImpl(stapler, servletRequest, new ArrayList<>(), tokenList);

        //when
        desc.configure(staplerRequest, json);

        //then
        assertThat(desc.isApplicable(AbstractProject.class), is(true));
        assertThat(desc.getCredentialsId(), is("bitbucket-credentials"));
        assertThat(desc.isDisableInprogressNotification(), is(true));
        assertThat(desc.getDisplayName(), is("Notify Bitbucket Instance"));
        assertThat(desc.isIncludeBuildNumberInKey(), is(true));
        assertThat(desc.isIgnoreUnverifiedSsl(), is(true));
        assertThat(desc.isPrependParentProjectKey(), is(true));
        assertThat(desc.getProjectKey(), is("JEN"));
        assertThat(desc.getStashRootUrl(), is("https://my.company.intranet/bitbucket"));
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
        FormValidation listBoxModel = doCheckStashServerBaseUrl("https://my.company.intranet/bitbucket");
        assertThat(listBoxModel.kind, is(FormValidation.Kind.OK));
    }
}
