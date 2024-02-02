package it.unitn.APCM.ACME.Guard.Objects;

/**
 * The type Client response.
 */
public class ClientResponse {
	/**
	 * The Path of the file.
	 */
	String path;
	/**
	 * The Auth, set to true if the client is authorized to open the file.
	 */
	boolean auth;
	/**
	 * The Write mode, set to true if the client is authorized to write on the file.
	 */
	boolean w_mode;
	/**
	 * The Text of the client response.
	 */
	String text;

	/**
	 * Instantiates a new Client response.
	 *
	 * @param path   the path
	 * @param auth   the auth
	 * @param w_mode the w mode
	 * @param text   the text
	 */
	public ClientResponse(String path, boolean auth, boolean w_mode, String text) {
        this.path = path;
        this.auth = auth;
        this.w_mode = w_mode;
        this.text = text;
    }

	/**
	 * Sets path.
	 *
	 * @param path the path
	 */
	public void set_path(String path) { this.path = path; }

	/**
	 * Sets authentication of the user.
	 *
	 * @param auth the auth
	 */
	public void set_auth(boolean auth) { this.auth = auth; }

	/**
	 * Sets text of the response.
	 *
	 * @param text the text
	 */
	public void set_text(String text) { this.text = text; }

	/**
	 * Sets write mode.
	 *
	 * @param w_mode the w mode
	 */
	public void set_w_mode(boolean w_mode) { this.w_mode = w_mode; }

	/**
	 * Gets path.
	 *
	 * @return the path
	 */
	public String get_path() { return this.path; }

	/**
	 * Gets authentication of the user.
	 *
	 * @return the auth
	 */
	public boolean get_auth() { return this.auth; }

	/**
	 * Gets text fo the response.
	 *
	 * @return the text
	 */
	public String get_text() { return this.text; }

	/**
	 * Gets write mode.
	 *
	 * @return the w mode
	 */
	public boolean get_w_mode() { return this.w_mode; }
}