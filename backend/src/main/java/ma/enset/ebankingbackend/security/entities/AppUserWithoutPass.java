package ma.enset.ebankingbackend.security.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.Collection;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppUserWithoutPass {
    private Long id;
    private String  username;
    private String email;
    private Collection<String> appRoles=new ArrayList<>();
}
