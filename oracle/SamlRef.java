import com.logalty.generation.saml.Roles;
import com.logalty.generation.saml.SamlConfig;
import com.logalty.generation.saml.SamlGenerator;

import java.util.Arrays;

/**
 * Emits a reference SAML document using the original Java SDK, so the Go port
 * can be diffed against it. Args: <pfxPath> <pfxPassword> [encoded|raw]
 */
public class SamlRef {

    public static void main(String[] args) throws Exception {
        String pfxPath = args[0];
        String pfxPassword = args[1];
        boolean encoded = args.length > 2 && args[2].equals("encoded");

        SamlGenerator.returnURLEncripted = encoded;

        SamlConfig config = new SamlConfig.Builder()
                .pfxPath(pfxPath)
                .pfxPassword(pfxPassword)
                .clientUrl("www.logalty.es")
                .login("jaumepallares")
                .fullName("Jaume Pallares")
                .password("1a35d9##")
                .mail("example@logalty.com")
                .rol(Roles.ADMIN)
                .group(1)
                .companies(Arrays.asList(311))
                .position("position")
                .emailAlerts(true)
                .readersGroup(Arrays.asList(1, 2))
                .build();

        System.out.print(SamlGenerator.generateSamlDocument(config));
    }
}
