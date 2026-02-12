// NOTE: This is a snippet of code that is used to integrate a server-side web application with Keycloak for authentication. It is not a complete aplication.

// SUPPORT AUTHENTICATION.
// Two authentication mechanisms are supported: OIDC (OpenID Connect) Authentication and Forms Authentication.
// Both mechanisms use cookies for session management, but differ in how authentication occurs.
// - OIDC (OpenID Connect) Authentication: Users authenticate via Keycloak with redirect-based login.
// - Forms Authentication: Legacy form-based login where users enter credentials validated against our database.
//      An HTTP context accessor is necessary in order to perform Forms Authentication. For more information on
//      Forms Authentication, see the following https://www.syncfusion.com/faq/blazor/general/how-do-i-do-cookie-authentication-in-blazor.
//
// Properly implemented OIDC Authentication is considered much more secure than Forms Authentication, but we keep
// Forms Authentication for supporting existing deployments that require it.
web_application_builder.Services.AddHttpContextAccessor();
web_application_builder.Services.AddScoped<AuthenticationStateProvider, UserAuthenticationManager>();
// New deployments should eventually use OIDC Authentication by default, but this is not yet enabled because it might break existing deployments
// that do not support it.
bool DO_NOT_ENFORCE_OPENID_CONNECT_AUTHENTICATION_BY_DEFAULT = false;
bool enforce_openid_connect_authentication = web_application_builder.Configuration.GetValue<bool>("Keycloak:EnforceOpenIdConnectAuthentication", DO_NOT_ENFORCE_OPENID_CONNECT_AUTHENTICATION_BY_DEFAULT);
if (enforce_openid_connect_authentication)
{
// USE OPENID CONNECT AUTHENTICATION.
// This provides a full OAuth2/OIDC (OpenID Connect) flow with redirect to Keycloak for login.
AuthenticationBuilder authentication_builder = web_application_builder.Services.AddAuthentication(authentication_options =>
{
    authentication_options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    authentication_options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    Log.Info("OIDC (OpenID Connect) Authentication is enforced. Users will be redirected to Keycloak for authentication.");
});

// GET THE KEYCLOAK CONFIGURATION NEEDED FOR OIDC AUTHENTICATION.
// The "authority" is the base URL (e.g., "http://localhost:8080/realms/your-app-realm") of the Keycloak server and realm that issues JSON Web Tokens (JWTs).
// This URL is used to discover Keycloak's public keys for validating JWT signatures and to verify that incoming tokens were issued by the expected Keycloak realm.
string keycloak_authority = web_application_builder.Configuration["Keycloak:Authority"];
// The "client ID" is the identifier for this application as registered in Keycloak (e.g., "your-app-client").
// This value is used both as the client_id in OIDC authentication requests and must match the "aud" (audience)
// claim in JWT tokens to ensure tokens are intended for this specific application.
string keycloak_client_id = web_application_builder.Configuration["Keycloak:ClientId"];
// This determines whether the OIDC metadata endpoint (used to discover Keycloak's configuration and public keys) must be accessed over HTTPS.
// When true, the application will only trust metadata retrieved over a secure HTTPS connection, mitigating man-in-the-middle attacks. This protection
// should be overridden ONLY for local development environments where Keycloak runs on HTTP.
bool REQUIRE_HTTPS_METADATA_BY_DEFAULT = true;
bool require_https_metadata = web_application_builder.Configuration.GetValue<bool>("Keycloak:RequireHttpsMetadata", REQUIRE_HTTPS_METADATA_BY_DEFAULT);

// CONFIGURE OIDC AUTHENTICATION.
authentication_builder.AddOpenIdConnect(openid_connect_authentication_options =>
{
    // CONFIGURE SESSION-BASED OIDC AUTHENTICATION FOR KEYCLOAK.
    // The meaning of these fields was discussed above.
    openid_connect_authentication_options.Authority = keycloak_authority;
    openid_connect_authentication_options.ClientId = keycloak_client_id;
    openid_connect_authentication_options.RequireHttpsMetadata = require_https_metadata;
    // We always use the Authorization Code request type (authentication flow), because it is very secure and recommended by current best practices.
    // This provides a server-side exchange of short-lived authorization code for tokens, which means tokens are never exposed to the browser/user agent.
    openid_connect_authentication_options.ResponseType = "code";
    // Use query string response mode instead of form_post to avoid the intermediate "OIDC Form_Post Response" page
    // that flashes during re-authentication. This is safe because with the Authorization Code flow, only the short-lived
    // authorization code is passed via the URL (not actual tokens) - the code is then exchanged server-side for tokens.
    openid_connect_authentication_options.ResponseMode = "query";
    // Save OAuth tokens (access token, refresh token, ID token) in the authentication cookie so that
    // the OnValidatePrincipal handler can check token expiration and refresh with Keycloak as needed.
    // This allows permission changes to be picked up on every request without interrupting the user.
    openid_connect_authentication_options.SaveTokens = true;

    // CONFIGURE THE OAUTH2/OIDC SCOPES TO REQUEST FROM KEYCLOAK.
    // Scopes determine what information (claims) we receive from Keycloak about the authenticated user.
    // We must clear the default scopes first because ASP.NET Core's OIDC middleware adds default scopes automatically.
    // By clearing and explicitly adding only what we need, we maintain precise control over what data is requested and
    // ensure we follow the principle of least privilege.
    openid_connect_authentication_options.Scope.Clear();
    // The "openid" scope is REQUIRED for OpenID Connect authentication. Without it, we would only have OAuth2 authorization, not authentication.
    openid_connect_authentication_options.Scope.Add("openid");
    // The "profile" scope provides standard user profile claims that we need: "preferred_username" (username) and "name" (full name).
    // These claims are extracted and used throughout the application to identify users.
    openid_connect_authentication_options.Scope.Add("profile");

    // MAP KEYCLOAK ROLES TO CLAIMS AFTER SUCCESSFUL AUTHENTICATION.
    openid_connect_authentication_options.Events = new OpenIdConnectEvents
    {
    OnTokenValidated = token_validated_context =>
    {
        // CATCH ANY ERRORS THAT OCCUR.
        // An uncaught exception in this function would be critically bad since it serves as a middleware
        // that could prevent users from being able to use the website at all. As such, all exceptions
        // are caught and logged.
        try
        {
            // MAP KEYCLOAK CLAIMS TO APPLICATION CLAIMS.
            // Keycloak roles are directly used as feature names for this application.
            ClaimsPrincipal original_principal = token_validated_context.Principal;
            IEnumerable<Claim> oidc_claims = original_principal.Claims;
            Claim[] app_claims = UserAuthorizationAlgorithm.GetAuthorizationClaimsForUserFromJsonWebToken(oidc_claims);
            // Create a new claims identity with the mapped claims.
            ClaimsIdentity app_identity = new ClaimsIdentity(app_claims, OpenIdConnectDefaults.AuthenticationScheme);
            // Replace the principal with the new one containing the mapped claims.
            token_validated_context.Principal = new ClaimsPrincipal(app_identity);
            Log?.Info($"Successfully mapped OIDC claims for user: {app_identity.Name}");
        }
        catch (Exception exception)
        {
            // INDICATE THAT AN ERROR OCCURRED.
            // If an exception occurs while validating a user's token, the user should be treated as if they are not authenticated since we
            // cannot guarantee that they are who they say they are. Failing authentication here will redirect the user back to the login page.
            Log?.Error($"Error mapping OpenID Connect (OIDC) claims: {exception.Message}");
            Log?.DebugTrace(exception.ToString());
            token_validated_context.Fail(exception);
        }

        // INDICATE THAT TOKEN VALIDATION COMPLETED.
        // The Task return value is required to indicate this handler finished executing, not whether authentication succeeded.
        return Task.CompletedTask;
    }
    };

    Log.Info($"Keycloak OpenID Connect (OIDC) authentication configured with authority: {keycloak_authority}");
});
