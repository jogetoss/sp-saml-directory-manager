package org.joget.marketplace;

public class AccountSettings {

    private String certificate;
    private String idp_sso_target_url;

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public String getIdpSsoTargetUrl() {
        return idp_sso_target_url;
    }

    public void setIdpSsoTargetUrl(String idp_sso_target_url) {
        this.idp_sso_target_url = idp_sso_target_url;
    }
}
