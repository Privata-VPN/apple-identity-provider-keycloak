package at.klausbetz.provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
            return unauthorized("invalid_token", "Bearer token is missing or invalid");
        }

        UserModel user = authResult.getUser();
        RealmModel realm = session.getContext().getRealm();

        IdentityProviderModel appleIdp = session.identityProviders().getByAlias("apple");
        if (appleIdp == null) {
            return error(Response.Status.NOT_FOUND, "apple_idp_not_configured",
                    "No Apple identity provider configured in this realm");
        }

        FederatedIdentityModel federatedIdentity = session.users()
                .getFederatedIdentity(realm, user, "apple");
        if (federatedIdentity == null || federatedIdentity.getToken() == null) {
            return ok("no_token", "No Apple token stored for this user");
        }

        try {
            JsonNode tokenJson = mapper.readTree(federatedIdentity.getToken());
            String refreshToken = textOrNull(tokenJson, "refresh_token");
            String accessToken = textOrNull(tokenJson, "access_token");
            String token = refreshToken != null ? refreshToken : accessToken;
            if (token == null) {
                return ok("no_token", "Stored token contains no revocable tokens");
            }
            String tokenTypeHint = refreshToken != null ? "refresh_token" : "access_token";

            AppleIdentityProviderConfig config = new AppleIdentityProviderConfig(appleIdp);
            AppleIdentityProvider provider = new AppleIdentityProvider(session, config);
            provider.prepareClientSecret(config.getClientId());

            SimpleHttp.Response response = SimpleHttp.doPost(APPLE_REVOKE_URL, session)
                    .param("client_id", config.getClientId())
                    .param("client_secret", config.getClientSecret())
                    .param("token", token)
                    .param("token_type_hint", tokenTypeHint)
                    .asResponse();

            if (response.getStatus() == 200) {
                logger.infof("Apple token revoked for user %s", user.getId());
                return ok("revoked", "Apple token revoked successfully");
            } else {
                String body = response.asString();
                logger.warnf("Apple revocation returned %d for user %s: %s",
                        response.getStatus(), user.getId(), body);
                return error(Response.Status.fromStatusCode(response.getStatus()),
                        "apple_error", "Apple returned status " + response.getStatus());
            }
        } catch (IOException e) {
            logger.error("Failed to revoke Apple token for user " + user.getId(), e);
            return error(Response.Status.INTERNAL_SERVER_ERROR, "revocation_failed", e.getMessage());
        }
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode child = node.get(field);
        return (child != null && !child.isNull()) ? child.asText() : null;
    }

    private static Response ok(String status, String message) {
        return Response.ok("{\"status\":\"" + status + "\",\"message\":\"" + message + "\"}")
                .type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    private static Response unauthorized(String error, String message) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("{\"error\":\"" + error + "\",\"message\":\"" + message + "\"}")
                .type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    private static Response error(Response.Status status, String error, String message) {
        return Response.status(status)
                .entity("{\"error\":\"" + error + "\",\"message\":\"" + message + "\"}")
                .type(MediaType.APPLICATION_JSON_TYPE).build();
    }
}
