package it.unitn.APCM.ACME.ServerCommon;

/**
 * The type Response.
 */
public class Response {
    /**
     * The Path hash.
     */
    String path_hash;
    /**
     * The Email.
     */
    String email;
    /**
     * The W mode.
     */
    boolean w_mode;
    /**
     * The Auth.
     */
    boolean auth;
    /**
     * The Key.
     */
    byte[] key;

    /**
     * Instantiates a new Response.
     *
     * @param path_hash the path hash
     * @param email     the email
     * @param w_mode    the w mode
     * @param auth      the auth
     * @param key       the key
     */
    public Response(String path_hash, String email, boolean w_mode, boolean auth, byte[] key) {
        this.path_hash = path_hash;
        this.email = email;
        this.w_mode = w_mode;
        this.auth = auth;
        this.key = key;
    }

    /**
     * Sets path hash.
     *
     * @param path_hash the path hash
     */
    public void set_path_hash(String path_hash) {this.path_hash = path_hash;}

    /**
     * Sets email.
     *
     * @param email the email
     */
    public void set_email(String email) {this.email = email;}

    /**
     * Sets w mode.
     *
     * @param w_mode the w mode
     */
    public void set_w_mode(boolean w_mode) {this.w_mode = w_mode;}

    /**
     * Sets key.
     *
     * @param key the key
     */
    public void set_key(byte[] key) {this.key = key;}

    /**
     * Sets auth.
     *
     * @param auth the auth
     */
    public void set_auth(boolean auth) {this.auth = auth;}

    /**
     * Gets path hash.
     *
     * @return the path hash
     */
    public String get_path_hash() {return this.path_hash;}

    /**
     * Gets email.
     *
     * @return the email
     */
    public String get_email() {return this.email;}

    /**
     * Gets w mode.
     *
     * @return the w mode
     */
    public boolean get_w_mode() {return this.w_mode;}

    /**
     * Get key byte [ ].
     *
     * @return the byte [ ]
     */
    public byte[] get_key() {return this.key;}

    /**
     * Gets auth.
     *
     * @return the auth
     */
    public boolean get_auth() {return this.auth;}
}