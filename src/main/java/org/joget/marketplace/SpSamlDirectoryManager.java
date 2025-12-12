package org.joget.marketplace;

import com.lastpass.saml.AttributeSet;
import com.lastpass.saml.IdPConfig;
import com.lastpass.saml.SAMLClient;
import com.lastpass.saml.SAMLException;
import com.lastpass.saml.SAMLInit;
import com.lastpass.saml.SAMLUtils;
import com.lastpass.saml.SPConfig;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.dao.UserDao;
import org.joget.directory.ext.DirectoryManagerAuthenticatorImpl;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManager;
import org.joget.directory.model.service.DirectoryManagerAuthenticator;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.model.service.WorkflowUserManager;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class SpSamlDirectoryManager extends SecureDirectoryManager {

    public SecureDirectoryManagerImpl dirManager;

    @Override
    public String getName() {
        return "SAML Service Provider Directory Manager";
    }

    @Override
    public String getDescription() {
        return "Directory Manager with support for SAML 2.0";
    }

    @Override
    public String getVersion() {
        return "8.0.5";
    }

    @Override
    public DirectoryManager getDirectoryManagerImpl(Map properties) {
        if (dirManager == null) {
            dirManager = new ExtSecureDirectoryManagerImpl(properties);
        } else {
            dirManager.setProperties(properties);
        }

        return dirManager;
    }

    @Override
    public String getLabel() {
        return "SAML Service Provider Directory Manager";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        String action = request.getParameter("action");
        if ("dmOptions".equals(action)) {
            super.webService(request, response);
        } else {
            doLogin(request, response);
        } //else {
        //response.sendError(HttpServletResponse.SC_NO_CONTENT);
        //}
    }

    void doLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String login = request.getParameter("login");
            if ("1".equals(login)) {

                DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
                SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

                //SecureDirectoryManagerImpl dm = getSecureDirectoryManagerImpl();
                String certificate = dmImpl.getPropertyString("certificate");
                String metadata = dmImpl.getPropertyString("metadata");
                String entityId = dmImpl.getPropertyString("entityId");
                if ((metadata != null) && (!"".equals(metadata))) {
                    metadata = metadata.trim();
                }

                SAMLInit.initialize();
                InputStream idpStr = new ByteArrayInputStream(metadata.getBytes());
                IdPConfig idpConfig = new IdPConfig(idpStr);

                Certificate aa = new Certificate();
                aa.loadCertificate(certificate);
                X509Certificate x509Cert = aa.getX509Cert();
                idpConfig.setCert(x509Cert);
                String spMetaData = getMetadata(entityId);
                InputStream spStr = new ByteArrayInputStream(spMetaData.getBytes());
                SPConfig spConfig = new SPConfig(spStr);
                SAMLClient client = new SAMLClient(spConfig, idpConfig);
                String requestId = SAMLUtils.generateRequestId();
                String authrequest = client.generateAuthnRequest(requestId);
                String url = client.getIdPConfig().getLoginUrl() + "?SAMLRequest=" + URLEncoder.encode(authrequest, "UTF-8");
                response.sendRedirect(url);

            } else if (request.getParameter("SAMLResponse") != null) {
                DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
                SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();
                String certificate = dmImpl.getPropertyString("certificate");
                boolean userProvisioningEnabled = Boolean.parseBoolean(dmImpl.getPropertyString("userProvisioning"));
                boolean userUpdateEnabled = Boolean.parseBoolean(dmImpl.getPropertyString("userUpdateEnabled"));

                String attrFirstName = dmImpl.getPropertyString("attrFirstName");
                String attrLastName = dmImpl.getPropertyString("attrLastName");
                String attrEmail = dmImpl.getPropertyString("attrEmail");

                String entityId = dmImpl.getPropertyString("entityId");
                String metadata = dmImpl.getPropertyString("metadata");
                if (certificate == null || certificate.isEmpty()) {
                    throw new CertificateException("IDP certificate is missing");
                }
                String authresponse = request.getParameter("SAMLResponse");
                AttributeSet aset;
                try {
                    SAMLInit.initialize();
                    InputStream idpStr = new ByteArrayInputStream(metadata.getBytes());
                    IdPConfig idpConfig = new IdPConfig(idpStr);
                    Certificate aa = new Certificate();
                    aa.loadCertificate(certificate);
                    X509Certificate x509Cert = aa.getX509Cert();
                    idpConfig.setCert(x509Cert);
                    String spMetaData = getMetadata(entityId);

                    InputStream spStr = new ByteArrayInputStream(spMetaData.getBytes());
                    SPConfig spConfig = new SPConfig(spStr);
                    SAMLClient client = new SAMLClient(spConfig, idpConfig);
                    try {
                        aset = client.validateResponse(authresponse);

                        String username = aset.getNameId();
                        Map<String, List<String>> attributes = aset.getAttributes();

                        List<String> emailValues = Optional.ofNullable(attributes.get(attrEmail))
                                .map(list -> (List<String>) list)
                                .orElse(Collections.emptyList());

                        List<String> firstNameValues = Optional.ofNullable(attributes.get(attrFirstName))
                                .map(list -> (List<String>) list)
                                .orElse(Collections.emptyList());
                        List<String> lastNameValues = Optional.ofNullable(attributes.get(attrLastName))
                                .map(list -> (List<String>) list)
                                .orElse(Collections.emptyList());

                        String email = emailValues.isEmpty() ? "" : emailValues.get(0);
                        String firstName = firstNameValues.isEmpty() ? "" : firstNameValues.get(0);
                        String lastName = lastNameValues.isEmpty() ? "" : lastNameValues.get(0);

                        if (checkAllStringsNotNull(firstName, email)) {
                            // process the attributes
                            User user = dmImpl.getUserByUsername(username);
                            if (user == null && userProvisioningEnabled) {
                                user = new User();
                                user.setId(username);
                                user.setUsername(username);
                                user.setTimeZone("0");
                                user.setActive(1);
                                user.setEmail(email);
                                user.setFirstName(firstName);
                                user.setLastName(lastName);

                                // set role
                                RoleDao roleDao = (RoleDao) AppUtil.getApplicationContext().getBean("roleDao");
                                Set roleSet = new HashSet();
                                Role r = roleDao.getRole("ROLE_USER");
                                if (r != null) {
                                    roleSet.add(r);
                                }
                                user.setRoles(roleSet);
                                // add user
                                UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
                                userDao.addUser(user);

                            } else if (user != null && userProvisioningEnabled && userUpdateEnabled) {
                                if (email != null && !email.isEmpty()) {
                                    user.setEmail(email);
                                }

                                if (firstName != null && !firstName.isEmpty()) {
                                    user.setFirstName(firstName);
                                }

                                if (lastName != null && !lastName.isEmpty()) {
                                    user.setLastName(lastName);
                                }

                                WorkflowUserManager wum = (WorkflowUserManager) AppUtil.getApplicationContext().getBean("workflowUserManager");
                                wum.setSystemThreadUser(true);

                                UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
                                userDao.updateUser(user);
                            } else if (user == null && !userProvisioningEnabled) {
                                response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                                return;
                            }

                            // verify license
                            PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
                            DirectoryManagerAuthenticator authenticator = (DirectoryManagerAuthenticator) pluginManager.getPlugin(DirectoryManagerAuthenticatorImpl.class.getName());
                            DirectoryManager wrapper = new DirectoryManagerWrapper(dmImpl, true);
                            authenticator.authenticate(wrapper, user.getUsername(), user.getPassword());

                            // get authorities
                            Collection<Role> roles = dm.getUserRoles(username);
                            List<GrantedAuthority> gaList = new ArrayList<>();
                            if (roles != null && !roles.isEmpty()) {
                                for (Role role : roles) {
                                    GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                                    gaList.add(ga);
                                }
                            }

                            // login user
                            UserDetails details = new WorkflowUserDetails(user);
                            UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(username, "", gaList);
                            result.setDetails(details);
                            SecurityContextHolder.getContext().setAuthentication(result);

                            SecurityContext securityContext = SecurityContextHolder.getContext();
                            securityContext.setAuthentication(result);

                            HttpSession session = request.getSession(true);
                            session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);

                            // add audit trail
                            WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
                            workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + ": " + true);

                            // redirect
                            String relayState = request.getParameter("RelayState");
                            if (relayState != null && !relayState.isEmpty()) {
                                response.sendRedirect(relayState);
                            } else {
                                SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
                                String savedUrl = "";
                                if (savedRequest != null) {
                                    savedUrl = savedRequest.getRedirectUrl();
                                } else {
                                    savedUrl = request.getContextPath();
                                }
                                response.sendRedirect(savedUrl);
                            }
                        } else {
                            LogUtil.info(getClassName(), "Check the arributes values" + attrEmail + "/" + attrFirstName + "/" + attrLastName);
                            response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                        }

                    } catch (SAMLException ex) {
                        LogUtil.error(getClassName(), ex, ex.getMessage());
                        response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                    }
                } catch (SAMLException ex) {
                    LogUtil.error(getClassName(), ex, ex.getMessage());
                    response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                }
            }

        } catch (Exception ex) {
            LogUtil.error(getClassName(), ex, ex.getMessage());
            response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
        }
    }

    private static boolean checkAllStringsNotNull(String... strings) {
        for (String str : strings) {
            if (str == null || str.isEmpty()) {
                return false;
            }
        }
        return true;
    }

    public static String getCallbackURL() {
        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String callbackUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            callbackUrl += ":" + request.getServerPort();
        }
        callbackUrl += request.getContextPath() + "/web/json/plugin/org.joget.marketplace.SpSamlDirectoryManager/service";
        return callbackUrl;
    }

    private String getMetadata(String entityId) {
        String spMetaData = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"\n"
                + "    xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"\n"
                + "    entityID=\"" + entityId + "\">\n"
                + "    <md:SPSSODescriptor\n"
                + "        protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n"
                + "        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress</md:NameIDFormat>\n"
                + "        <md:AssertionConsumerService index=\"1\" isDefault=\"true\"\n"
                + "            Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n"
                + "            Location=\"" + entityId + "\"/>\n"
                + "    </md:SPSSODescriptor>\n"
                + "</md:EntityDescriptor>";
        return spMetaData;
    }

    public java.security.cert.Certificate getCertificate(String certificateString) {
        try {

            byte[] certificateData = certificateString.getBytes(StandardCharsets.UTF_8.name());
            ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateData);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate certificate = certificateFactory.generateCertificate(inputStream);
            return certificate;
        } catch (CertificateException | UnsupportedEncodingException ex) {
            LogUtil.error(getClassName(), ex, ex.getMessage());
        }
        return null;
    }

    @Override
    public String getPropertyOptions() {
        UserSecurityFactory f = (UserSecurityFactory) new SecureDirectoryManagerImpl(null);
        String usJson = f.getUserSecurity().getPropertyOptions();
        usJson = usJson.replaceAll("\\n", "\\\\n");

        String addOnJson = "";
        if (SecureDirectoryManagerImpl.NUM_OF_DM > 1) {
            for (int i = 2; i <= SecureDirectoryManagerImpl.NUM_OF_DM; i++) {
                addOnJson += ",{\nname : 'dm" + i + "',\n label : '@@app.edm.label.addon@@',\n type : 'elementselect',\n";
                addOnJson += "options_ajax : '[CONTEXT_PATH]/web/json/plugin/org.joget.plugin.directory.SecureDirectoryManager/service',\n";
                addOnJson += "url : '[CONTEXT_PATH]/web/property/json/getPropertyOptions'\n}";
            }
        }

        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String acsUrl = request.getScheme() + "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            acsUrl += ":" + request.getServerPort();
        }
        acsUrl += request.getContextPath() + "/web/json/plugin/org.joget.marketplace.SpSamlDirectoryManager/service";
        String entityId = acsUrl;

        String json = AppUtil.readPluginResource(getClass().getName(), "/properties/app/spSamlDirectoryManager.json", new String[]{entityId, acsUrl, usJson, addOnJson}, true, "messages/SpSamlDirectoryManager");
        //String json = AppUtil.readPluginResource(getClass().getName(), "/properties/app/spSamlDirectoryManager.json", new String[]{entityId, usJson, addOnJson}, true, "messages/SpSamlDirectoryManager");
        return json;
    }
}
