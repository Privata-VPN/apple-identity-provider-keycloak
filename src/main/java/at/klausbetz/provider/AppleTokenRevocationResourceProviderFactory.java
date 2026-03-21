package at.klausbetz.provider;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class AppleTokenRevocationResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "apple-token-revocation";

    @Override
    public AppleTokenRevocationResourceProvider create(KeycloakSession session) {
        return new AppleTokenRevocationResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
