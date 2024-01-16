package it.unitn.APCM.ACME.ServerCommon;

public class ClientResponse {
    int id;
    String path_hash;
    boolean w_mode;
    String text;

    /*
     * SETTER
     */
    public void set_id(int id) {this.id = id;}

    public void set_path_hash(String path_hash) {this.path_hash = path_hash;}

    public void set_text(String text) {this.text = text;}

    public void set_w_mode(boolean w_mode) {this.w_mode = w_mode;}

    /*
     * GETTER
     */
    public int get_id() {return this.id;}

    public String get_path_hash() {return this.path_hash;}

    public String get_text() {return this.text;}

    public boolean get_w_mode() {return this.w_mode;}
}