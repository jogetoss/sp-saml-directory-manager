package org.joget.marketplace;

import java.util.List;
import java.util.Map;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.PluginThread;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.directory.model.service.UserSecurity;
import org.joget.marketplace.spsaml.GraphMailSender;
import org.joget.plugin.base.HiddenPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.plugin.directory.UserSecurityImpl;

public class ExtUserSecurityImpl extends UserSecurityImpl implements HiddenPlugin {

    public static final String EMAIL_PROVIDER_GRAPH = "graph";

    public ExtUserSecurityImpl() {
        super();
    }
    
    @Override
    public String getName() {
        return "SAML Service Provider User Security";
    }

    @Override
    public String getDescription() {
        return "User Security for SAML Service Provider";
    }

    @Override
    public String getVersion() {
        return "8.0.3";
    }
    
    @Override
    public String getLabel() {
        return "SAML Service Provider User Security";
    }

    /**
     * Override login form footer to insert SSO login button
     */
    @Override
    public String getLoginFormFooter() {
        DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
        SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

        // original footer
        String content = "";
        
        if ("true".equals(getPropertyString("enableForgotPassword"))) {
            content += "<a rel=\"popup\" style=\"cursor:pointer;text-decoration:underline;\" onclick=\"forgotPassword();return false;\">"+ResourceBundleUtil.getMessage("app.edm.label.forgotPassword")+"</a>\n";

            String contextPath = AppUtil.getRequestContextPath();
            content += "<script>function forgotPassword(){new PopupDialog('" + contextPath + "/web/json/plugin/"+getClassName()+"/service?a=fp', ' ').init();}</script>";

            String token = getForgotPasswordToken();
            if (token != null) {
                content += "<script>$(document).ready(function(){new PopupDialog('" + contextPath + "/web/json/plugin/"+getClassName()+"/service?a=fpcp&t="+token+"', ' ').init();});</script>";
            }
        }

        for (UserSecurity us : getSubUserSecurityImpls()) {
            content += us.getLoginFormFooter();
        }
        String redirectUrl = SpSamlDirectoryManager.getCallbackURL()+"?login=1";
        // append login button
        content += "<style>\n"
                + "#openIDLogin {\n"
                + "    background: " + dmImpl.getPropertyString("buttonBackgroundColor") + ";\n"
                + "    padding: 10px 20px;\n"
                + "    border-radius: 3px;\n"
                + "    text-align: left;\n"
                + "    display: block;\n"
                + "    width: fit-content;\n"
                + "    color: " + dmImpl.getPropertyString("buttonTextColor") + ";\n"
                + "    margin: 20px 100px;\n"
                + "}\n"
                + "#icon {\n"
                + "padding-right: 20px;\n"
                + "}\n"
                + "</style>";
        content += "<a href=\"" + redirectUrl + "\" id=\"openIDLogin\"><i id=\"icon\" class=\"" + dmImpl.getPropertyString("buttonIcon") + "\"></i>" + dmImpl.getPropertyString("buttonText") + "</a>";

        return content;
    }

    /**
     * Override this method so that the templates will be read from the main
     * non-OSGI classloader
     *
     * @param template
     * @param model
     * @return
     */
    @Override
    protected String getTemplate(String template, Map model) {
        PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
        String content = pluginManager.getPluginFreeMarkerTemplate(model, UserSecurityImpl.class.getName(), "/templates/" + template + ".ftl", null);
        return content;
    }

    /**
     * Treat Microsoft Graph as configured mail so forgot password, password reset
     * and user creation emails are not skipped when no SMTP host is set
     */
    @Override
    public boolean isSmtpNotConfigured() {
        if (isGraphEnabled()) {
            GraphMailSender sender = createGraphMailSender(getProperties());
            return !sender.isConfigured() || (getPropertyString("from").isEmpty() && sender.usesFromPlaceholder());
        }
        return super.isSmtpNotConfigured();
    }

    /**
     * Send notification emails through Microsoft Graph instead of SMTP when enabled
     */
    @Override
    protected void sendEmail(User user, String subject, String message, Map<String, String> data) {
        if (!isGraphEnabled()) {
            super.sendEmail(user, subject, message, data);
            return;
        }
        if (isSmtpNotConfigured()) {
            LogUtil.warn(getClass().getName(), "Send email to user " + user.getUsername() + " failed, Microsoft Graph not configured");
            return;
        }
        try {
            String emailSubject = populateEmailData(subject, user, data);
            if (emailSubject != null) {
                emailSubject = emailSubject.replace("\n", "").replace("\r", "");
            }
            final String finalSubject = emailSubject;
            final String body = AppUtil.processHashVariable(populateEmailData(message, user, data), null, null, null);
            final String from = getPropertyString("from");
            final String username = user.getUsername();
            final List<String> to = GraphMailSender.splitAddresses(user.getEmail());
            final List<String> cc = GraphMailSender.splitAddresses(getPropertyString("cc"));
            final boolean html = "true".equalsIgnoreCase(getPropertyString("isHtml"));
            final GraphMailSender sender = createGraphMailSender(getProperties());

            // Send in the background like the SMTP EmailTool; a lambda avoids a lazily loaded class in the shared org.joget.marketplace package.
            Thread thread = new PluginThread(() -> {
                try {
                    sender.send(from, to, cc, finalSubject, body, html);
                    LogUtil.info(ExtUserSecurityImpl.class.getName(), "Email sent via Microsoft Graph to user " + username + ", subject=" + finalSubject);
                } catch (Exception e) {
                    LogUtil.error(ExtUserSecurityImpl.class.getName(), e, "Send email via Microsoft Graph to user " + username + " failed");
                }
            });
            thread.setDaemon(true);
            thread.start();
        } catch (Exception e) {
            LogUtil.error(getClass().getName(), e, "Send email via Microsoft Graph to user " + user.getUsername() + " failed");
        }
    }

    protected boolean isGraphEnabled() {
        return EMAIL_PROVIDER_GRAPH.equals(getPropertyString("emailProvider"));
    }

    public static GraphMailSender createGraphMailSender(Map properties) {
        return new GraphMailSender(
                value(properties, "graphTenantId"),
                value(properties, "graphClientId"),
                SecurityUtil.decrypt(value(properties, "graphClientSecret")),
                value(properties, "graphTokenUrl"),
                value(properties, "graphScope"),
                value(properties, "graphSendMailUrl"));
    }

    private static String value(Map properties, String key) {
        Object value = properties == null ? null : properties.get(key);
        return value == null ? "" : value.toString();
    }
}
