package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.kohsuke.stapler.*;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import org.mockito.MockedStatic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

/**
 * Created by Vlad Medvedev on 27.01.2016.
 * vladislav.medvedev@devfactory.com
 */
public class DescriptorImplTest {

    /**
     * Class under test.
     */
    private static StashNotifier.DescriptorImpl desc;

    private static JSONObject json;
    private static Jenkins jenkins;
    private static MockedStatic<Jenkins> mockedJenkins;
    private static MockedStatic<CredentialsProvider> mockedCredentialsProvider;

    @BeforeClass
    public static void setUp() {
        mockedJenkins = mockStatic(Jenkins.class);
        mockedCredentialsProvider = mockStatic(CredentialsProvider.class);

        jenkins = mock(Jenkins.class);
        when(Jenkins.get()).thenReturn(jenkins);

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

    @AfterClass
    public static void close() {
        mockedJenkins.close();
        mockedCredentialsProvider.close();
    }

    @Test
    public void testConfigure() throws Exception {
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
        assertThat(desc.getStashRootUrl(), is("https://my.company.intranet/bitbucket"));
    }

    @Test
    public void test_doFillCredentialsIdItems_project_null() {
        //given
        when(jenkins.hasPermission(Item.CONFIGURE)).thenReturn(false);

        //when
        ListBoxModel listBoxModel = desc.doFillCredentialsIdItems(null);

        //then
        assertThat(listBoxModel, is(not(nullValue())));
    }

    @Test
    public void test_doFillCredentialsIdItems_no_permission() {
        //given
        Item project = mock(Item.class);
        when(project.hasPermission(Item.CONFIGURE)).thenReturn(false);
        when(jenkins.hasPermission(Item.CONFIGURE)).thenReturn(false);

        //when
        ListBoxModel listBoxModel = desc.doFillCredentialsIdItems(project);

        //then
        assertThat(listBoxModel, is(not(nullValue())));
    }

    @Test
    public void test_doFillCredentialsIdItems_has_permission() {
        //given
        Item project = mock(Item.class);
        when(project.hasPermission(Item.CONFIGURE)).thenReturn(true);
        when(CredentialsProvider.lookupCredentials(
                any(),
                any(Item.class),
                any(Authentication.class),
                anyList()
        )).thenReturn(new ArrayList<>());

        //when
        ListBoxModel listBoxModel = desc.doFillCredentialsIdItems(project);

        //then
        assertThat(listBoxModel, is(not(nullValue())));
    }

    @Test
    public void test_doCheckStashServerBaseUrl_empty() throws Exception {
        //when
        desc.setStashRootUrl("");
        FormValidation listBoxModel = desc.doCheckStashServerBaseUrl("");

        //then
        assertThat(listBoxModel.kind, is(FormValidation.Kind.ERROR));
    }

    @Test
    public void test_doCheckStashServerBaseUrl() throws Exception {
        //when
        FormValidation listBoxModel = desc.doCheckStashServerBaseUrl("https://my.company.intranet/bitbucket");

        //then
        assertThat(listBoxModel.kind, is(FormValidation.Kind.OK));
    }
}
