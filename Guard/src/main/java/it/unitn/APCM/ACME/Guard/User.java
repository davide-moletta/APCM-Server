package it.unitn.APCM.ACME.Guard;

public class User {
    private String email;
    private String groups;
    private int admin;

    public User(String email, String groups, int admin) {
        this.email = email;
        this.groups = groups;
        this.admin = admin;
    }

    public String getEmail() {
        return email;
    }

    public String getGroups() {
        return groups;
    }

    public int getAdmin() {
        return admin;
    }
}
