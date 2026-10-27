package at.klausbetz.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.io.IOException;
import java.util.List;

/**
 * Revokes the stored Apple tokens of the calling user. A realm can have several Apple IdP
 * aliases (one per Apple developer team), so every linked identity of an Apple IdP is revoked.
 */
public class AppleTokenRevocationResource {

    private static final Logger logger = Logger.getLogger(AppleTokenRevocationResource.class);
    private static final String APPLE_REVOKE_URL = "https://appleid.apple.com/auth/revoke";
    private static final ObjectMapper mapper = new ObjectMapper();

    private final KeycloakSession session;

    public AppleTokenRevocationResource(KeycloakSession session) {
        this.session = session;
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeToken(@Context HttpHeaders headers) {
        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session)
                .setHeaders(headers)
                .authenticate();

        if (authResult == null) {
            return json(Response.Status.UNAUTHORIZED, body("error", "invalid_token", "Bearer token is missing or invalid"));
        }

        UserModel user = authResult.user();
        RealmModel realm = session.getContext().getRealm();

        List<FederatedIdentityModel> appleLinks = session.users().getFederatedIdentitiesStream(realm, user)
                .filter(link -> appleIdp(link.getIdentityProvider()) != null)
                .toList();

        ArrayNode providers = mapper.createArrayNode();
        int revoked = 0;
        int failed = 0;
        for (FederatedIdentityModel link : appleLinks) {
            String status = revoke(user, link, appleIdp(link.getIdentityProvider()));
            providers.addObject().put("alias", link.getIdentityProvider()).put("status", status);
            if ("revoked".equals(status)) {
                revoked++;
            } else if ("failed".equals(status)) {
                failed++;
            }
        }

        if (failed > 0) {
            ObjectNode body = body("error", "apple_error", "Apple token revocation failed for " + failed + " provider(s)");
            body.set("providers", providers);
            return json(Response.Status.BAD_GATEWAY, body);
        }
        ObjectNode body = revoked > 0
                ? body("status", "revoked", "Apple token revoked successfully")
                : body("status", "no_token", "No Apple token stored for this user");
        body.set("providers", providers);
        return json(Response.Status.OK, body);
    }

    private IdentityProviderModel appleIdp(String alias) {
        IdentityProviderModel idp = session.identityProviders().getByAlias(alias);
        return idp != null && AppleIdentityProviderFactory.PROVIDER_ID.equals(idp.getProviderId()) ? idp : null;
    }

    private String revoke(UserModel user, FederatedIdentityModel link, IdentityProviderModel idp) {
        String alias = link.getIdentityProvider();
        if (link.getToken() == null) {
            return "no_token";
        }
        try {
            AppleIdentityProviderConfig config = new AppleIdentityProviderConfig(idp);
            AppleStoredToken stored = AppleStoredToken.parse(link.getToken(), config.getClientId());
            if (stored == null) {
                return "no_token";
            }

            AppleIdentityProvider provider = new AppleIdentityProvider(session, config);
            provider.prepareClientSecret(stored.getClientId());

            SimpleHttp.Response response = SimpleHttp.doPost(APPLE_REVOKE_URL, session)
                    .param("client_id", stored.getClientId())
                    .param("client_secret", config.getClientSecret())
                    .param("token", stored.getToken())
                    .param("token_type_hint", stored.getTokenTypeHint())
                    .asResponse();

            if (response.getStatus() == 200) {
                logger.infof("Apple token revoked for user %s alias %s client %s", user.getId(), alias, stored.getClientId());
                return "revoked";
            }
            logger.warnf("Apple revocation returned %d for user %s alias %s client %s: %s",
                    response.getStatus(), user.getId(), alias, stored.getClientId(), response.asString());
            return "failed";
        } catch (IOException e) {
            logger.errorf(e, "Failed to revoke Apple token for user %s alias %s", user.getId(), alias);
            return "failed";
        }
    }

    private static ObjectNode body(String key, String value, String message) {
        return mapper.createObjectNode().put(key, value).put("message", message);
    }

    private static Response json(Response.Status status, ObjectNode body) {
        return Response.status(status).entity(body.toString()).type(MediaType.APPLICATION_JSON_TYPE).build();
    }
}
