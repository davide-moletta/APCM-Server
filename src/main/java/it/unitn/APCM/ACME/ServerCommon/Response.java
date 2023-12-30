package it.unitn.APCM.ACME.ServerCommon;

public class Response {
    int id;
    String path_hash;
    String email;
    boolean w_mode;
    boolean auth;
    String key;

    /*
     * SETTER
     */
    public void set_id(int id) {this.id = id;}

    public void set_path_hash(String path_hash) {this.path_hash = path_hash;}

    public void set_email(String email) {this.email = email;}

    public void set_w_mode(boolean w_mode) {this.w_mode = w_mode;}

    public void set_key(String key) {this.key = key;}

    public void set_auth(boolean auth) {this.auth = auth;}

    /*
     * GETTER
     */
    public int get_id() {return this.id;}

    public String get_path_hash() {return this.path_hash;}

    public String get_email() {return this.email;}

    public boolean get_w_mode() {return this.w_mode;}

    public String get_key() {return this.key;}

    public boolean get_auth() {return this.auth;}
}