package at.klausbetz.provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.JsonWebToken;

import java.io.IOException;

/**
 * Revocable token taken from the Apple token response stored on a federated identity.
 */
final class AppleStoredToken {

    private static final ObjectMapper mapper = new ObjectMapper();

    private final String token;
    private final String tokenTypeHint;
    private final String clientId;

    private AppleStoredToken(String token, String tokenTypeHint, String clientId) {
        this.token = token;
        this.tokenTypeHint = tokenTypeHint;
        this.clientId = clientId;
    }

    /**
     * Returns null when the stored response holds neither a refresh nor an access token.
     * Apple binds tokens to the client that redeemed the authorization code (the App ID for
     * native sign-in, the Services ID for web) and only revokes them for that client, so the
     * client id comes from the stored id_token audience, falling back to the IdP client id.
     */
    static AppleStoredToken parse(String storedToken, String defaultClientId) throws IOException {
        JsonNode json = mapper.readTree(storedToken);
        if (json == null || !json.isObject()) {
            return null;
        }
        String refreshToken = textOrNull(json, "refresh_token");
        String accessToken = textOrNull(json, "access_token");
        String token = refreshToken != null ? refreshToken : accessToken;
        if (token == null) {
            return null;
        }
        String audience = audience(textOrNull(json, "id_token"));
        return new AppleStoredToken(
                token,
                refreshToken != null ? "refresh_token" : "access_token",
                audience != null ? audience : defaultClientId);
    }

    String getToken() {
        return token;
    }

    String getTokenTypeHint() {
        return tokenTypeHint;
    }

    String getClientId() {
        return clientId;
    }

    private static String audience(String idToken) {
        if (idToken == null) {
            return null;
        }
        try {
            String[] audience = new JWSInput(idToken).readJsonContent(JsonWebToken.class).getAudience();
            return audience != null && audience.length > 0 ? audience[0] : null;
        } catch (JWSInputException e) {
            return null;
        }
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode child = node.get(field);
        return child != null && !child.isNull() && !child.asText().isBlank() ? child.asText() : null;
    }
}
