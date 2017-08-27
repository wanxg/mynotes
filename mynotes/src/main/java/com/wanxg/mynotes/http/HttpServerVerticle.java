package com.wanxg.mynotes.http;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.core.UserManagerAction;
import com.wanxg.mynotes.database.DataBaseQueries;
import com.wanxg.mynotes.database.DatabaseVerticle;
import com.wanxg.mynotes.util.EventBusAddress;
import com.wanxg.mynotes.util.FailureCode;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.eventbus.ReplyException;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.providers.FacebookAuth;
import io.vertx.ext.auth.oauth2.providers.GoogleAuth;
import io.vertx.ext.sync.Sync;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.AuthHandler;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.handler.FaviconHandler;
import io.vertx.ext.web.handler.RedirectAuthHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.handler.StaticHandler;
import io.vertx.ext.web.handler.UserSessionHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;
import io.vertx.ext.web.templ.HandlebarsTemplateEngine;

public class HttpServerVerticle extends AbstractVerticle {

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpServerVerticle.class);
	
	private static final long COOKIE_MAX_AGE = 60*60*24*1;
	
	private static final String GOOGLE_CLIENT_ID="700050092358-3il62628u6t9q2mu2h8ivb63dbtbde3h.apps.googleusercontent.com";
	private static final String GOOGLE_CLIENT_SECRET="r7CsiXU4RQk5CSr4-2fGjPtx";
	private static final String GOOGLE_REDIRECT_URI="https://localhost:8080/googleoauth2callback";
	private static final String GOOGLE_TOKEN_VERIFICATION_URI="https://www.googleapis.com/oauth2/v3/tokeninfo?";
	private static final String GOOGLE_USER_PROFILE_URI="https://www.googleapis.com/plus/v1/people/{userId}?";
	//private static final String GOOGLE_USER_PROFILE_URI2="https://www.googleapis.com/userinfo/v2/me?";
	//private static final String GOOGLE_USER_PROFILE_URI3="https://www.googleapis.com/oauth2/v2/userinfo?";
	
	private static final String FACEBOOK_APP_ID="1830829080578913";
	private static final String FACEBOOK_APP_SECRET="3181ceb68c2ef7462671f0c14f1af5df";
	private static final String FACEBOOK_REDIRECT_URI="https://localhost:8080/facebookauth2callback";
	private static final String FACEBOOK_DEBUG_TOKEN_URI="https://graph.facebook.com/debug_token?";
	private static final String FACEBOOK_USER_PROFILE_URI="https://graph.facebook.com/me?";
	private static final String FACEBOOK_USER_PROFILE_PIC_URI="https://graph.facebook.com/{userId}/picture?width=150&height=150";
	
	private final HandlebarsTemplateEngine engine = HandlebarsTemplateEngine.create();

	@Override
	public void start(Future<Void> startFuture) throws Exception {

		final Router router = Router.router(vertx);

		router.route().handler(CookieHandler.create());
		router.route().handler(BodyHandler.create());
		router.route().handler(SessionHandler.create(LocalSessionStore.create(vertx)).setSessionTimeout(10*60*1000));

		// A user session handler, so that the user is stored in the session between requests
		router.route().handler(UserSessionHandler.create(DatabaseVerticle.authProvider));

		// An auth handler that redirect to login page if user is not stored in the session
		AuthHandler authHandler = RedirectAuthHandler.create(DatabaseVerticle.authProvider, "/login");

		router.route("/").handler(authHandler);
		router.get("/profile").handler(authHandler);
		router.get("/account").handler(authHandler);
		
		

		// handle log in
		router.route("/login").handler(this::handleLogin);

		// handle google log in
		router.route("/googlelogin").handler(this::handleGoogleLogin);
		router.route("/googleoauth2callback").handler(this::handleGoogleCallback);
		
	
		// handle facebook log in
		router.route("/facebooklogin").handler(this::handleFacebookLogin);
		router.route("/facebookauth2callback").handler(this::handleFacebookCallback);
		
		
		// handle sign up
		router.post("/signup").handler(this::handleSignUp);

		// handle logout, clear the authentication and cookies and direct to login page
		router.route("/logout").handler(this::handleLogout);

		// handle home page after login
		router.get("/").handler(this::handleHomePage);

		// handle profile page
		router.get("/profile").handler(Sync.fiberHandler(this::handleProfilePage));
		
		// handle http post request for updating profile
		router.post("/profile").handler(Sync.fiberHandler(this::handleManageProfile));
		
		// handle http post request for updating local user password
		router.post("/account").handler(Sync.fiberHandler(this::handleManageAccount));
		
		
		// route for static resources
		router.route().handler(StaticHandler.create().setCachingEnabled(false));

		router.route().handler(FaviconHandler.create("webroot/pic/favicon.ico"));

		router.route().failureHandler(this::handleFailure);
		
		LOGGER.info("Starting a HTTP web server on port 8080");
		vertx.createHttpServer(new HttpServerOptions()
				.setKeyStoreOptions(new JksOptions().setPath("server-keystore.jks").setPassword("secret")).setSsl(true))
				.requestHandler(router::accept).listen(8080, ar -> {
					if (ar.succeeded()) {
						LOGGER.info("HTTP server running on port " + 8080);
						startFuture.complete();
					} else {
						LOGGER.error("Could not start a HTTP server", ar.cause());
						startFuture.fail(ar.cause());
					}

				});
		
	}

	/**
	 * Handle log in
	 * 
	 */
	private void handleLogin(RoutingContext ctx) {

		
		// Login with cookie
		if (ctx.request().method().equals(HttpMethod.GET)) {

			LOGGER.debug("[handleLogin]Handling HTTP GET for login page");
			boolean isAuthenticated = ctx.user() != null;

			if (isAuthenticated)
				doRedirect(ctx.response(), "/");
			
			else {
				
				Cookie tokenCookie = ctx.getCookie("auth_token");
				LOGGER.debug("[handleLogin]auth_token : " + (tokenCookie==null?"null":tokenCookie.getValue()));
				
				
				Cookie userHashCookie = ctx.getCookie("user_hash");
				LOGGER.debug("[handleLogin]user_hash : " + (userHashCookie==null?"null":userHashCookie.getValue()));
				
				if(tokenCookie!=null && userHashCookie!=null){
					
					String userHash = userHashCookie.getValue();
					String[] strings = tokenCookie.getValue().split("_",2);
					String clearToken = strings[0];
					String tokenId = strings[1];
					
					LOGGER.debug("[handleLogin]Both cookies existing, performing automatic login with cookies.");
					
					JsonObject authInfo = new JsonObject().put("username", tokenId).put("password", clearToken);
					DatabaseVerticle.authProvider.setAuthenticationQuery(DataBaseQueries.AUTHENTICATE_QUERY_ON_TOKEN).authenticate(authInfo, Sync.fiberHandler(res -> {
						if (res.succeeded()) {
							// user authenticated
							User user = res.result();
							LOGGER.info("[handleLogin]Automatic login with cookies successful.");
							LOGGER.debug("[handleLogin]User principal: " + user.principal());
							ctx.setUser(user);
							
							// Retrieving user profile with user id
							
							JsonObject retrieveUserProfileRequest = new JsonObject().put("userId", userHash);
							DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.FIND_USER_PROFILE.toString());
							Message<JsonObject> result = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(),retrieveUserProfileRequest,options,h));
							JsonObject userProfile = result.body();
							
							//Reissue a new auth token and delete the old one 
							LOGGER.info("[handleLogin]Issue a new token.");
							DeliveryOptions opt = new DeliveryOptions().addHeader("user", UserManagerAction.MANAGE_TOKEN.toString()).addHeader("sub_action", UserManagerAction.REISSUE_TOKEN.toString());
							String newClearToken = generateAuthToken();
							JsonObject reissueTokenRequest = new JsonObject()
																.put("token_id", tokenId)
																.put("userId", userHash)
																.put("auth_token", newClearToken)
																.put("valid_to", new Date().getTime()+COOKIE_MAX_AGE*1000);
							
							Message<Integer> returnedTokenId = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(),reissueTokenRequest,opt,h));
							
							Integer newTokenId = returnedTokenId.body();
							
							//creating a new cookie
							LOGGER.info("[handleLogin]Create a new auth token cookie.");
							ctx.addCookie(Cookie.cookie("auth_token",newClearToken+"_"+newTokenId).setMaxAge(COOKIE_MAX_AGE));
							LOGGER.debug("[handleLogin]A cookie is created : {" + ctx.getCookie("auth_token").getName() +":"+ctx.getCookie("auth_token").getValue()+"}");
							
							LOGGER.info("[handleLogin]Setting user into session.");
							ctx.session().put("userProfile", userProfile);
							
							doRedirect(ctx.request().response(), "/");
							
						}
						else{
							LOGGER.info("[handleLogin]Automatic login with cookies failed. Removing cookies");
							// we have to delete the cookies from browser and delete the token from db
							deleteToken(tokenId);
							tokenCookie.setMaxAge(0);
							userHashCookie.setMaxAge(0);
							renderHandlebarsPage(ctx, "login");
						}
					}));
					
				}
				else
					renderHandlebarsPage(ctx, "login");
			}
		}

		// Login with user input
		else if (ctx.request().method().equals(HttpMethod.POST)) {
			
			LOGGER.debug("[handleLogin]Received http post request on /login");
			
			JsonObject profile = ctx.session().get("userProfile");
			
			if(profile!=null){
				doRedirect(ctx.response(), "/");
				return;
			}

			//String email = ctx.request().getFormAttribute("login_email");
			//String password = ctx.request().getFormAttribute("login_password");
			//boolean rememberMe = "remember_me".equals(ctx.request().getFormAttribute("remember_me"));
			
			String email = ctx.getBodyAsJson().getString("login_email");
			String password = ctx.getBodyAsJson().getString("login_password");
			boolean rememberMe = ctx.getBodyAsJson().getBoolean("remember_me");

			LOGGER.debug(email + ", " + password + ", " + rememberMe);
			
			
			if (email == null || password == null || email.isEmpty() || password.isEmpty()) {
				LOGGER.error("[handleLogin]No email or password provided in the form.");
				//ctx.fail(400);
				ctx.response().putHeader("content-type", "text/html").setStatusCode(400).end("No email or password provided!");
			} else {

				JsonObject authInfo = new JsonObject().put("username", email).put("password", password);
				DatabaseVerticle.authProvider.setAuthenticationQuery(DataBaseQueries.AUTHENTICATE_QUERY_ON_LOCAL_USER).authenticate(authInfo, Sync.fiberHandler(res -> {
					
					if (res.succeeded()) {
						// user authenticated
						User user = res.result();
						LOGGER.debug("[handleLogin]User principal: " + user.principal());
						ctx.setUser(user);
						
						
						//Retrieving user profile
						
						JsonObject retrieveUserProfileRequest = new JsonObject().put("email", email);
						DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.FIND_USER_PROFILE.toString());
						Message<JsonObject> result = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(),retrieveUserProfileRequest,options,h));
						JsonObject userProfile = result.body();
						
						LOGGER.info("[handleLogin]Adding user profile into session: " + userProfile);
						
						ctx.session().put("userProfile", userProfile);
						
						if(rememberMe && ctx.getCookie("auth_token")==null){
							
							// login with remember me checked
							
							String clearToken = generateAuthToken();
							
							// sending the auth token to database
							JsonObject rememberMeRequest = new JsonObject()
																.put("userId", userProfile.getString("USER_ID"))
																.put("auth_token", clearToken)
																.put("valid_to", new Date().getTime()+COOKIE_MAX_AGE*1000);
							
							DeliveryOptions opt = new DeliveryOptions().addHeader("user", UserManagerAction.REMEMBER_ME.toString());
							LOGGER.debug("[handleLogin]Calling user manager LOG_IN_REMEMBER_ME with rememberMeRequest: " + rememberMeRequest);
							
							vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), rememberMeRequest, opt,
									
									reply -> {
										
										if (reply.failed()) {
											
											LOGGER.warn("[handleLogin]Remember me request failed with error:  " + reply.cause());
											LOGGER.warn("[handleLogin]Token will not be generated.");
											ctx.response().putHeader("content-type", "text/html").setStatusCode(400).end(reply.cause().getMessage());
										}
										
										else{
											
											String tokenId = reply.result().body().toString();
											
											LOGGER.info("[handleLogin]Remember me request successful.");
											LOGGER.debug("[handleLogin]Returned token id: " + tokenId);
											
											LOGGER.debug("[handleLogin]Creating cookies");
											
											//creating cookie
											ctx.addCookie(Cookie.cookie("auth_token",clearToken+"_"+tokenId).setMaxAge(COOKIE_MAX_AGE));
											LOGGER.debug("[handleLogin]A cookie is created : {" + ctx.getCookie("auth_token").getName() +":"+ctx.getCookie("auth_token").getValue()+"}");
											
											ctx.addCookie(Cookie.cookie("user_hash", userProfile.getString("USER_ID")).setMaxAge(COOKIE_MAX_AGE));
											LOGGER.debug("[handleLogin]A cookie is created : {" + ctx.getCookie("user_hash").getName() +":"+ctx.getCookie("user_hash").getValue()+"}");
										
											LOGGER.info("[handleLogin]Token has bee stored, cookies are created. User login has been remembered. Setting user into session.");
											
											ctx.response().putHeader("content-type", "text/html").end("Login OK!");
										}
									}
							);
						
						} else {
							// login without remember me
							LOGGER.debug("[handleLogin]Login OK without remember me.");
							
							ctx.response().putHeader("content-type", "text/html").end("Login OK!");
						}
					
					} else {
						
						LOGGER.debug("[handleLogin]Login failed due to invalid email or password.");
						//ctx.fail(403); // Failed login
						ctx.response().putHeader("content-type", "text/html").setStatusCode(403).end("Login failed!");
					}
				}));
			}
		}
	}
	
	
	/**
	 * 
	 *  Handle google login
	 *  
	 */

	private void handleGoogleLogin(RoutingContext ctx){
		
		LOGGER.debug("received login request from google login button.");
		
		OAuth2Auth oauth2 = GoogleAuth.create(vertx, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
		
		String authorization_uri = oauth2.authorizeURL(new JsonObject()
			    .put("redirect_uri", GOOGLE_REDIRECT_URI)
			    .put("scope", "email profile"));
			   
		doRedirect(ctx.response(), authorization_uri);
		
	}
	
	/**
	 * 
	 *  Handle google callback
	 * 
	 */
	
	private void handleGoogleCallback(RoutingContext ctx){
		
		LOGGER.debug("[HandleGoogleCallback]Received google call back with Authorization Code.");
		
		String googleAuthCode = ctx.request().getParam("code");
		
		JsonObject tokenConfig = new JsonObject()
			    .put("code", googleAuthCode)
			    .put("redirect_uri", GOOGLE_REDIRECT_URI);
		
		OAuth2Auth oauth2 = GoogleAuth.create(vertx, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
		
		
		oauth2.getToken(tokenConfig, res -> {
			  if (res.failed()) {
			    LOGGER.error("[HandleGoogleCallback]Access token retrieval error: " + res.cause().getMessage());
			    ctx.fail(FailureCode.SOCIAL_LOGIN_ERROR.getCode());
			    
			  } else {
			    // Get the access token object (the authorization code is given from the previous step).
			    AccessToken token = res.result();
			    
			    LOGGER.debug("[HandleGoogleCallback]Received token : " + token.principal());
			    String accessToken = token.principal().getString("access_token");
			    LOGGER.debug("[HandleGoogleCallback]access_token : " + accessToken );
			    LOGGER.debug("[HandleGoogleCallback]id_token : " + token.principal().getString("id_token"));
			    
			    JsonObject params = new JsonObject().put("id_token",token.principal().getString("id_token"));

			    // verify id token
			    oauth2.api(HttpMethod.GET, GOOGLE_TOKEN_VERIFICATION_URI, params, verify ->{
			    	
			    	if(verify.failed()){
			    		LOGGER.error("[HandleGoogleCallback]Access token verification error: " + verify.cause().getMessage());
			    		ctx.fail(FailureCode.SOCIAL_LOGIN_ERROR.getCode());
			    	}
			    	
			    	else{
			    		
			    		LOGGER.debug("[HandleGoogleCallback]Token verification result: " + verify.result());
			    		JsonObject result = verify.result();
			    		
			    		ctx.setUser(token);
			    		
			    		String email = result.getString("email");
			    		String externalId = result.getString("sub");
			    		LOGGER.debug("email: " + email + ", external id: " + externalId);
			    		
			    		JsonObject meParams = new JsonObject().put("access_token", accessToken);
			    		
			    		oauth2.api(HttpMethod.GET, GOOGLE_USER_PROFILE_URI.replace("{userId}", externalId), meParams, Sync.fiberHandler(me ->{
			    			
			    			if(me.failed()){
			    				LOGGER.error("[HandleGoogleCallback]Retrieving user profile failed : " + me.cause().getMessage());
			    				ctx.fail(FailureCode.SOCIAL_LOGIN_ERROR.getCode());
			    			}
			    			
			    			else{
			    				
			    				String username = me.result().getString("displayName");
			    				String photoUrl = me.result().getJsonObject("image").getString("url");
			    				if(photoUrl.indexOf("sz=50")!=0)
			    					photoUrl = photoUrl.replace("sz=50", "sz=150");
			    				String firstName = me.result().getJsonObject("name").getString("givenName");
			    				String lastName = me.result().getJsonObject("name").getString("familyName");
			    				String gender = me.result().getString("gender");
			    				
			    				LOGGER.debug("[HandleGoogleCallback]Retrieved google user info: " + externalId + ", " + email + ", "+ username + ", " + firstName + ", " + lastName + ", " + photoUrl + ", " + gender);
			    				
			    				// Social sign up
			    				
			    				JsonObject socialSignUpRequest = new JsonObject()
			    													.put("email", email)
			    													.put("username",username)
			    													.put("firstName", firstName)
			    													.put("lastName", lastName)
			    													.put("photoUrl", photoUrl)
			    													.put("gender", gender)
			    													.put("externalId", externalId)
			    													.put("socialProvider", "Google");
			    				
								DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.SOCIAL_SIGN_UP.toString());
			    				Message<JsonObject> signUpResult = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(),socialSignUpRequest,options,h));
			    				
			    				LOGGER.debug("[HandleGoogleCallback]Social sign up successful, user profile: " + signUpResult.body());
			    				
			    				ctx.session().put("userProfile", signUpResult.body());
			    				doRedirect(ctx.request().response(), "/");
			    			}
			    		}));
			    	}
			    });
			  }
			});
	}
	
	/**
	 * 
	 *  Handle facebook login
	 *  
	 */
	
	private void handleFacebookLogin(RoutingContext ctx){
		
		LOGGER.debug("received login request from facebook login button.");
		
		OAuth2Auth oauth2 = FacebookAuth.create(vertx, FACEBOOK_APP_ID, FACEBOOK_APP_SECRET);
		
		String authorization_uri = oauth2.authorizeURL(new JsonObject()
			    .put("redirect_uri", FACEBOOK_REDIRECT_URI)
			    .put("scope", "email,public_profile")
			    .put("response_type", "token"));
		
		doRedirect(ctx.response(), authorization_uri);
		
	}
	
	/**
	 *  Handle facebook callback
	 * 
	 */
	
	private void handleFacebookCallback(RoutingContext ctx){
		
		LOGGER.debug("[HandleFacebookCallback]Received facebook call back with Authorization Code.");
		
		LOGGER.debug(ctx.request().absoluteURI());

		if(ctx.request().getParam("error")!=null){
			
			LOGGER.error("ERROR:" + ctx.request().getParam("error_reason"));
			ctx.fail(FailureCode.SOCIAL_LOGIN_ERROR.getCode());
			return;
			
		}
		
		String facebookAuthCode = ctx.request().getParam("code");
		
		JsonObject tokenConfig = new JsonObject()
			    .put("code", facebookAuthCode)
			    .put("redirect_uri", FACEBOOK_REDIRECT_URI);
		
		OAuth2Auth oauth2 = FacebookAuth.create(vertx, FACEBOOK_APP_ID, FACEBOOK_APP_SECRET);
		
		//Request access token
		oauth2.getToken(tokenConfig, res -> {
			
			  if (res.failed()) {
				  
			    LOGGER.error("[HandleFacebookCallback]Access token retrieval error: " + res.cause().getMessage());
			    ctx.fail(FailureCode.SOCIAL_LOGIN_ERROR.getCode());
			    
			  } else {
				  
			    AccessToken token = res.result();
			    
			    LOGGER.debug("[HandleFacebookCallback]Received token : " + token.principal());
			    
			    String accessToken = token.principal().getString("access_token");
			    
			    //Verify access token
			    JsonObject params = new JsonObject().put("input_token",accessToken).put("access_token", FACEBOOK_APP_ID+"|"+FACEBOOK_APP_SECRET);
			    oauth2.api(HttpMethod.GET, FACEBOOK_DEBUG_TOKEN_URI, params, verify ->{
			    	
			    	if(verify.failed()){
			    		
			    		LOGGER.error("[HandleFacebookCallback]Access token verification error: " + verify.cause().getMessage());
			    		ctx.fail(FailureCode.SOCIAL_LOGIN_ERROR.getCode());
			    	}
			    		
			    	else{
			    		
			    		LOGGER.debug("[HandleFacebookCallback]Verification result: " + verify.result());
			    		
			    		ctx.setUser(token);
			    		
			    		JsonObject meParams = new JsonObject().put("fields","id,name,email,picture,first_name,last_name,gender").put("access_token", accessToken);
			    		
			    		oauth2.api(HttpMethod.GET, FACEBOOK_USER_PROFILE_URI, meParams, Sync.fiberHandler(me ->{
			    			
			    			if(me.failed()){
			    				LOGGER.error("[HandleFacebookCallback]Retrieving user profile failed : " + me.cause().getMessage());
			    				ctx.fail(FailureCode.SOCIAL_LOGIN_ERROR.getCode());
			    				return;
			    			}
			    			
			    			else{
			    				String externalId = me.result().getString("id");
			    				String email = me.result().getString("email");
			    				String username = me.result().getString("name");
			    				//String photoUrl = me.result().getJsonObject("picture").getJsonObject("data").getString("url");
			    				String photoUrl = FACEBOOK_USER_PROFILE_PIC_URI.replace("{userId}", externalId);
			    				
			    				String firstName = me.result().getString("first_name");
			    				String lastName = me.result().getString("last_name");
			    				String gender = me.result().getString("gender");
			    				
			    				LOGGER.debug("[HandleFacebookCallback]Retrieved facebook user info: " + externalId + ", " + email + ", "+ username + ", " + firstName + ", " + lastName + ", " + photoUrl + ", " + gender);
			    				
			    				// Social sign up
			    				
			    				JsonObject socialSignUpRequest = new JsonObject()
			    													.put("email", email)
			    													.put("username",username)
			    													.put("firstName", firstName)
			    													.put("lastName", lastName)
			    													.put("photoUrl", photoUrl)
			    													.put("gender", gender)
			    													.put("externalId", externalId)
			    													.put("socialProvider", "Facebook");
			    				
								DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.SOCIAL_SIGN_UP.toString());
			    				Message<JsonObject> result = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(),socialSignUpRequest,options,h));
			    				
			    				LOGGER.debug("[HandleFacebookCallback]Social sign up successful, user profile: " + result.body());
			    				
			    				ctx.session().put("userProfile", result.body());
			    				doRedirect(ctx.request().response(), "/");
			    			}
			    		}));
			    	}
			    });
			  }
			});
	}
	

	/**
	 * Handle HTTP POST for sign up
	 * 
	 * @param ctx
	 */
	private void handleSignUp(RoutingContext ctx) {

		LOGGER.debug("[handleSignUp]Received http post request on: " + ctx.request().absoluteURI());

		LOGGER.debug("received body: " + ctx.getBodyAsString());
		LOGGER.debug("received headers: ");
		ctx.request().headers().forEach(System.out::println);

		JsonObject profile = ctx.session().get("userProfile");
		
		LOGGER.debug("user: " + ctx.user());
		LOGGER.debug("profile: " + profile);
		
		Boolean isProfileCreated = ctx.getBodyAsJson().getBoolean("isProfileCreated");
		
		// when user has been logged in but session is expired
		if(Boolean.TRUE.equals(isProfileCreated) && (profile==null || profile.isEmpty())){
			ctx.clearUser();
			LOGGER.info("[handleSignUp]Session expired.");
			ctx.response().putHeader("content-type", "text/html").setStatusCode(401).end("Unauthorized request.");
			return;
		}
		
		String username = ctx.getBodyAsJson().getString("username");
		String email = ctx.getBodyAsJson().getString("email");
		String password = ctx.getBodyAsJson().getString("password");
		
		
		JsonObject signUpRequest = new JsonObject();

		signUpRequest.put("user_name", username)
				.put("signup_email", email)
				.put("signup_password", password);
				
		if(profile!=null)
			signUpRequest.put("pid",profile.getInteger("PID"));

		LOGGER.debug("[handleSignUp]Calling user manager sign_up with signUpRequest: " + signUpRequest);

		DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.SIGN_UP.toString());

		vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), signUpRequest, options,
				reply -> {

					if (reply.failed()) {
						LOGGER.error("[handleSignUp] Sign up failed:  " + reply.cause());
						//ReplyException exception = (ReplyException) reply.cause();
						//ctx.fail(exception.failureCode());
						ctx.response().putHeader("content-type", "text/html").setStatusCode(805).end("Signup failed!");
						
					} else {
						
						if(profile!=null){
							
							JsonObject userProfile = (JsonObject)reply.result().body();
							LOGGER.info("[handleSignUp]User profile updated to: " + userProfile);
							ctx.response().putHeader("content-type", "text/html").end("Local user has been created and linked with current user profile.");
						}
						
						else {
							
							JsonObject userProfile = (JsonObject)reply.result().body();
							LOGGER.info("[handleSignUp]User profile created: " + userProfile);
	
							JsonObject authInfo = new JsonObject().put("username", email)
									.put("password", password);
	
							LOGGER.debug("authInfo: " + authInfo);
	
							DatabaseVerticle.authProvider.setAuthenticationQuery(DataBaseQueries.AUTHENTICATE_QUERY_ON_LOCAL_USER).authenticate(authInfo, res -> {
								if (res.succeeded()) {
									User user = res.result();
									ctx.setUser(user);
									ctx.session().put("userProfile", userProfile);
									
									ctx.response().putHeader("content-type", "text/html").end("Signup OK!");
	
								} else {
									
									LOGGER.error("[handleSignUp]Login failed after signup : " + res.cause().getMessage());
									ctx.response().putHeader("content-type", "text/html").setStatusCode(403).end("Signup failed!");
								}
							});
						}
					}

				});
	}

	/**
	 * Handle log out
	 * 
	 * @param ctx
	 */
	private void handleLogout(RoutingContext ctx) {
		LOGGER.debug("Logging out ...");
		
		Cookie userCookie = ctx.getCookie("user_hash");
		
		if(userCookie!=null){
			LOGGER.debug("Cookie:" + userCookie);
			userCookie.setMaxAge(0);
		}
		
		Cookie tokenCookie = ctx.getCookie("auth_token");
		
		if(tokenCookie!=null){
			LOGGER.debug("Cookie:" + tokenCookie);
			String[] strings = tokenCookie.getValue().split("_",2);
			String tokenId = strings[1];
			deleteToken(tokenId);
			tokenCookie.setMaxAge(0);
		}
		
		ctx.clearUser();
		ctx.session().destroy();
		// Redirect back to the login page
		doRedirect(ctx.response(), "/");
	}

	/**
	 * Handle HTTP GET on /
	 * 
	 * @param ctx
	 */

	private void handleHomePage(RoutingContext ctx) {
		LOGGER.debug("[handleHomePage]Requesting home page /");

		LOGGER.debug("[handleHomePage]Auth user with principal: " + ctx.user().principal());
		

		JsonObject userProfile = ctx.session().get("userProfile");
				
		LOGGER.debug("[handleHomePage]User profile: " + userProfile);
		
		// if user profile is not stored in the session, redirect to login page
		if(userProfile==null || userProfile.isEmpty()){
			
			ctx.clearUser();
			doRedirect(ctx.response(), "/");
			
		}
			
		else {
			ctx.put("userProfile", userProfile);
			renderHandlebarsPage(ctx, "home");
		}
	}
	
	
	
	/**
	 * Handle HTTP POST on /profile
	 * 
	 * @param ctx
	 */
	
	private void handleManageProfile(RoutingContext ctx) {
		
		LOGGER.info("[handleManageProfile]Received http post request on /profile");
		
		JsonObject profile = ctx.session().get("userProfile");
		
		// when session is expired
		if(profile==null || profile.isEmpty()){
			ctx.clearUser();
			LOGGER.info("[handleManageProfile]Session expired.");
			ctx.response().putHeader("content-type", "text/html").setStatusCode(401).end("Unauthorized request.");
			return;
		}
				
		String action = ctx.getBodyAsJson().getString("action");
		
		if("update".equals(action)){
			
			Integer pid = profile.getInteger("PID");
			/*
			String username = ctx.request().getParam("username");
			String firstName = ctx.request().getParam("firstname");
			String lastName = ctx.request().getParam("lastname");
			String radioGender = ctx.request().getParam("gender");
			*/
			
			String username = ctx.getBodyAsJson().getString("username");
			String firstName = ctx.getBodyAsJson().getString("firstname");
			String lastName = ctx.getBodyAsJson().getString("lastname");
			String radioGender = ctx.getBodyAsJson().getString("gender");
			
			
			Integer gender;
			
			if("female".equals(radioGender))
				gender = 0;
			else if("male".equals(radioGender))
				gender = 1;
			else
				gender = null;
			
			LOGGER.debug("[handleManageProfile]Received form values: " + username + ", " + firstName + ", " + lastName + ", " + gender + ", " + pid);
			
			//Updating user profile
			
			JsonObject updateUserProfileRequest = new JsonObject().put("username", username).put("firstName", firstName).put("lastName", lastName).put("gender", gender).put("pid", pid);
			
			DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.MANAGE_USER_PROFILE.toString()).addHeader("sub_action", UserManagerAction.UPDATE_USER_PROFILE.toString());
			Message<JsonObject> result = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(),updateUserProfileRequest,options,h));
			JsonObject userProfile = result.body();
			ctx.session().put("userProfile", userProfile);
			ctx.response().putHeader("content-type", "text/html").end("User profile has been updated successfully.");
			
		}
		
		else
			//ctx.fail(FailureCode.ILLEGAL_ARGUMENT.getCode());
			ctx.response().putHeader("content-type", "text/html").setStatusCode(403).end("Illegal argument.");

		//ctx.reroute(HttpMethod.GET, "/profile");
		
	}
	
	
	
	
	/**
	 * Handle HTTP GET on /profile
	 * 
	 * @param ctx
	 */

	private void handleProfilePage(RoutingContext ctx) {
		LOGGER.info("[handleProfilePage]Requesting profile page /");

		JsonObject profile = ctx.session().get("userProfile");
		
		if(profile==null || profile.isEmpty()){
			ctx.clearUser();
			doRedirect(ctx.response(), "/");
			return;
		}
		
		//Retrieving user profile
		
		JsonObject retrieveUserProfileRequest = new JsonObject().put("pid", profile.getInteger("PID")).put("load_social_accounts", true);
		
		DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.FIND_USER_PROFILE.toString());
		Message<JsonObject> result = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(),retrieveUserProfileRequest,options,h));
		JsonObject userProfile = result.body();
		
		LOGGER.info("[handleProfilePage]Updating user profile in the session: " + userProfile);
		
		
		LOGGER.debug("Total: " + userProfile.getJsonArray("socialAccounts").size());
		
		LOGGER.debug("Social accounts: " + userProfile.getJsonArray("socialAccounts"));
		
		
		boolean isFemale = userProfile.getInteger("GENDER")!=null&&userProfile.getInteger("GENDER")==0? true : false;
		boolean isMale = userProfile.getInteger("GENDER")!=null&&userProfile.getInteger("GENDER")==1? true : false;
		userProfile.put("isFemale", isFemale);
		userProfile.put("isMale", isMale);
		
		ctx.session().put("userProfile", userProfile);
		ctx.put("userProfile", userProfile);
		renderHandlebarsPage(ctx, "profile");
		
	}
	
	/**
	 * 
	 * Handle HTTP POST on /account
	 * 
	 * @param ctx
	 */
	
	private void handleManageAccount(RoutingContext ctx){
		
		LOGGER.info("[handleManageAccount]Retrieved http post request on /account");
		
		JsonObject profile = ctx.session().get("userProfile");
		
		// when session is expired
		if(profile==null || profile.isEmpty()){
			ctx.clearUser();
			ctx.response().putHeader("content-type", "text/html").setStatusCode(401).end("Unauthorized request.");
			return;
		}

		String uid = profile.getString("USER_ID");
		
		LOGGER.debug(ctx.getBodyAsString());
		
		String oldPassword = ctx.getBodyAsJson().getString("old_password");
		
		LOGGER.debug("old password:" + oldPassword);
		
		String newPassword = ctx.getBodyAsJson().getString("new_password");
		
		LOGGER.debug("new password:" + newPassword);
		
		String email = profile.getString("EMAIL");
		
		JsonObject authInfo = new JsonObject().put("username", email).put("password", oldPassword);

		LOGGER.debug("authInfo: " + authInfo);

		DatabaseVerticle.authProvider.setAuthenticationQuery(DataBaseQueries.AUTHENTICATE_QUERY_ON_LOCAL_USER).authenticate(authInfo, Sync.fiberHandler(res -> {
			if (res.succeeded()) {
				
				LOGGER.debug("[handleManageAccount]Old password is correct.");
				
				JsonObject updatePasswordRequest = new JsonObject().put("uid", uid).put("password", newPassword);
				
				DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.MANAGE_LOCAL_USER.toString()).addHeader("sub_action", UserManagerAction.UPDATE_USER_PASSWORD.toString());
				
				Message<String> result = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(),updatePasswordRequest,options,h));
		
				ctx.response().putHeader("content-type", "text/html").end(result.body());
				
			} else {
				
				LOGGER.debug("[handleManageAccount]Old password invalid: " + res.cause().getMessage());
				ctx.response().putHeader("content-type", "text/html").setStatusCode(403).end("Old password invalid.");
			}
		}));
		
		
		
		
	}
	

	/**
	 * Handle HTTP request failure for different status codes
	 * 
	 * @param ctx
	 */
	private void handleFailure(RoutingContext ctx) {

		LOGGER.debug("[handleFailure]Status code: " + ctx.statusCode());
		LOGGER.debug("[handleFailure]Failure: " + ctx.failure());
		LOGGER.debug("[handleFailure]Path:" + ctx.request().path());
		
		int statusCode = 0;
		
		if(ctx.statusCode()==-1 && ctx.failure() instanceof io.vertx.core.eventbus.ReplyException){
			
			ReplyException re = (ReplyException)ctx.failure();
			statusCode = re.failureCode();
		}
		
		else 
			statusCode = ctx.statusCode();

		switch (statusCode) {

		case 404:

			ctx.put("error_message", "Requested resource doesn't exist.");
			renderHandlebarsPage(ctx, "error");
			break;

		case 403:

			ctx.put("login_failed", true);
			renderHandlebarsPage(ctx, "login");
			break;

		case 804: //Email already exists
			
			ctx.put("signup_failed", true);
			renderHandlebarsPage(ctx, "login");
			break;
			
		case 805: //ILLEGAL_ARGUMENT
			
			ctx.put("error_message", "Internal Server Error");
			renderHandlebarsPage(ctx, "error");
			break;	
			

		case 806: //Socal login error
			
			ctx.put("social_login_failed", true);
			renderHandlebarsPage(ctx, "login");
			break;	
			
		case 901:
			
			ctx.put("error_message", "Database Error!");
			//ctx.failure().printStackTrace();
			renderHandlebarsPage(ctx, "error");
			break;
			
		default:

			ctx.put("error_message", ctx.failure());
			renderHandlebarsPage(ctx, "error");

		}
	}

	/**
	 * call handlebars template engine to render login.hbs
	 * 
	 * @param ctx
	 */
	private void renderHandlebarsPage(RoutingContext ctx, String page) {

		ctx.put("page", page.substring(0, 1).toUpperCase() + page.substring(1));
		engine.render(ctx, "templates/", "_" + page + ".hbs", res -> {
			if (res.succeeded()) {
				ctx.response().putHeader("Content-Type", "text/html");
				ctx.response().end(res.result());
			} else {
				ctx.fail(res.cause());
			}
		});
	}
	

	/**
	 * Redirect to url
	 * 
	 * @param response
	 * @param url
	 */
	private void doRedirect(HttpServerResponse response, String url) {
		response.putHeader("location", url).setStatusCode(302).end();
	}
	
	
	/**
	 *  to delete the token from db
	 * 
	 */
	
	private void deleteToken(String tokenId){

		DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.MANAGE_TOKEN.toString()).addHeader("sub_action", UserManagerAction.DELETE_TOKEN.toString());
		JsonObject deleteTokenRequest = new JsonObject().put("token_id", tokenId);
		vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), deleteTokenRequest, options, reply -> {
			
			if (reply.succeeded()) {
				LOGGER.info(reply.result().body().toString());
			}
			else {
				LOGGER.info("Deleting token failed : " + reply.cause());
			}
		});
	}
	
	/**
	 *  Generate authentication token for cookie 
	 */
	
	public static String generateAuthToken(){
		SecureRandom random = new SecureRandom();
		return new BigInteger(130, random).toString(32);
	}

}
