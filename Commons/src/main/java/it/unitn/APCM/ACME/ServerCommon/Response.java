package it.unitn.APCM.ACME.ServerCommon;

/**
 * The type Response.
 */
public class Response {
    /**
     * The Path hash of the file.
     */
    String path_hash;
    /**
     * The Email of the user.
     */
    String email;
    /**
     * The W mode set to true if the user is allowed to write on the file.
     */
    boolean w_mode;
    /**
     * The Auth set to true if the user is authorized to open the file.
     */
    boolean auth;
    /**
     * The Key to decrypt the file.
     */
    byte[] key;

    /**
     * Instantiates a new Response.
     *
     * @param path_hash the path hash string
     * @param email     the email fo the user
     * @param w_mode    the boolean that represent if the write mode is enabled
     * @param auth      the boolean that represent if the user is authenticated
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
     * Sets write mode.
     *
     * @param w_mode the write mode
     */
    public void set_w_mode(boolean w_mode) {this.w_mode = w_mode;}

    /**
     * Sets key.
     *
     * @param key the key
     */
    public void set_key(byte[] key) {this.key = key;}

    /**
     * Sets authentication of the user.
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
     * Gets write mode.
     *
     * @return the write mode
     */
    public boolean get_w_mode() {return this.w_mode;}

    /**
     * Get key byte [ ].
     *
     * @return the byte [ ]
     */
    public byte[] get_key() {return this.key;}

    /**
     * Gets authentication of the user.
     *
     * @return the auth
     */
    public boolean get_auth() {return this.auth;}
}