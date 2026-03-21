package at.klausbetz.provider;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class AppleTokenRevocationResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public AppleTokenRevocationResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new AppleTokenRevocationResource(session);
    }

    @Override
    public void close() {
    }
}
