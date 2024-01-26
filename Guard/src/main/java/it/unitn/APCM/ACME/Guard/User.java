package it.unitn.APCM.ACME.Guard;

/**
 * The type User.
 */
public class User {
    /**
     * The Email.
     */
    private final String email;
    /**
     * The Groups.
     */
    private final String groups;
    /**
     * The Admin privilege.
     */
    private final int admin;

    /**
     * Instantiates a new User.
     *
     * @param email  the email
     * @param groups the groups
     * @param admin  the admin
     */
    public User(String email, String groups, int admin) {
        this.email = email;
        this.groups = groups;
        this.admin = admin;
    }

    /**
     * Gets email.
     *
     * @return the email
     */
    public String getEmail() {
        return email;
    }

    /**
     * Gets groups.
     *
     * @return the groups
     */
    public String getGroups() {
        return groups;
    }

    /**
     * Gets admin.
     *
     * @return the admin
     */
    public int getAdmin() {
        return admin;
    }
}
