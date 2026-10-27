package at.klausbetz.provider;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AppleStoredTokenTest {

    private static final String SERVICES_ID = "com.example.web";

    private static String idToken(String payload) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8))
                + "." + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + ".c2ln";
    }

    @Test
    void givenNativeTokenResponse_whenParsing_thenRefreshTokenIsRevokedForTheAppId() throws Exception {
        String stored = "{\"access_token\":\"at\",\"refresh_token\":\"rt\",\"id_token\":\""
                + idToken("{\"aud\":\"com.example.app\",\"sub\":\"001\"}") + "\"}";

        AppleStoredToken token = AppleStoredToken.parse(stored, SERVICES_ID);

        assertEquals("rt", token.getToken());
        assertEquals("refresh_token", token.getTokenTypeHint());
        assertEquals("com.example.app", token.getClientId());
    }

    @Test
    void givenAudienceArray_whenParsing_thenFirstAudienceIsUsed() throws Exception {
        String stored = "{\"refresh_token\":\"rt\",\"id_token\":\""
                + idToken("{\"aud\":[\"com.example.app\"],\"sub\":\"001\"}") + "\"}";

        assertEquals("com.example.app", AppleStoredToken.parse(stored, SERVICES_ID).getClientId());
    }

    @Test
    void givenNoIdToken_whenParsing_thenIdpClientIdIsUsed() throws Exception {
        AppleStoredToken token = AppleStoredToken.parse("{\"access_token\":\"at\",\"refresh_token\":\"\"}", SERVICES_ID);

        assertEquals("at", token.getToken());
        assertEquals("access_token", token.getTokenTypeHint());
        assertEquals(SERVICES_ID, token.getClientId());
    }

    @Test
    void givenMalformedIdToken_whenParsing_thenIdpClientIdIsUsed() throws Exception {
        AppleStoredToken token = AppleStoredToken.parse("{\"refresh_token\":\"rt\",\"id_token\":\"not-a-jwt\"}", SERVICES_ID);

        assertEquals(SERVICES_ID, token.getClientId());
    }

    @Test
    void givenNoRevocableToken_whenParsing_thenNothingIsReturned() throws Exception {
        assertNull(AppleStoredToken.parse("{\"id_token\":\"" + idToken("{\"aud\":\"com.example.app\"}") + "\"}", SERVICES_ID));
        assertNull(AppleStoredToken.parse("null", SERVICES_ID));
    }
}
