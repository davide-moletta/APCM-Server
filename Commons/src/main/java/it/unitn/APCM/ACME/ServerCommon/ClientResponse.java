package it.unitn.APCM.ACME.ServerCommon;

public class ClientResponse {
    String path;
    boolean auth;
    boolean w_mode;
    String text;


    public ClientResponse(String path, boolean auth, boolean w_mode, String text) {
        this.path = path;
        this.auth = auth;
        this.w_mode = w_mode;
        this.text = text;
    }
    
    public void set_path(String path) {
        this.path = path;
    }

    public void set_auth(boolean auth) {
        this.auth = auth;
    }

    public void set_text(String text) {
        this.text = text;
    }

    public void set_w_mode(boolean w_mode) {
        this.w_mode = w_mode;
    }

    public String get_path() {
        return this.path;
    }

    public boolean get_auth() {
        return this.auth;
    }

    public String get_text() {
        return this.text;
    }

    public boolean get_w_mode() {
        return this.w_mode;
    }
}