package ma.enset.ebankingbackend.security.entities;


import lombok.Data;

@Data
public class RoleUserForm {
    private String username;
    private String roleName;
}
