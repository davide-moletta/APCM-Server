package it.unitn.APCM.ACME.ServerCommon;

public class UserPrivilege {
    private int admin;
    private String groups;

    public UserPrivilege(int admin, String groups){
        this.admin = admin;
        this.groups = groups;
    }

    public int getAdmin(){ return this.admin; }

    public String getGroups(){ return this.groups; }
}
