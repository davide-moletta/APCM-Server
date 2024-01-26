package it.unitn.APCM.ACME.ServerCommon;

/**
 * The type User privilege.
 */
public class UserPrivilege {
    /**
     * The Admin.
     */
    private final int admin;
    /**
     * The Groups.
     */
    private final String groups;

    /**
     * Instantiates a new User privilege.
     *
     * @param admin  the admin
     * @param groups the groups
     */
    public UserPrivilege(int admin, String groups){
        this.admin = admin;
        this.groups = groups;
    }

    /**
     * Get admin int.
     *
     * @return the int
     */
    public int getAdmin(){ return this.admin; }

    /**
     * Get groups string.
     *
     * @return the string
     */
    public String getGroups(){ return this.groups; }
}
