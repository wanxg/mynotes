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

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.eventbus.ReplyException;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
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
import io.vertx.ext.web.templ.TemplateEngine;

public class HttpServerVerticle extends AbstractVerticle {

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpServerVerticle.class);
	
	private static final long COOKIE_MAX_AGE = 60*60*24*1;
	
	private static final String GOOGLE_CLIENT_ID="700050092358-3il62628u6t9q2mu2h8ivb63dbtbde3h.apps.googleusercontent.com";
	private static final String GOOGLE_CLIENT_SECRET="r7CsiXU4RQk5CSr4-2fGjPtx";
	private static final String GOOGLE_REDIRECT_URI="https://localhost:8080/googleoauth2callback";
	
	private static final String FACEBOOK_APP_ID="1830829080578913";
	private static final String FACEBOOK_APP_SECRET="3181ceb68c2ef7462671f0c14f1af5df";
	private static final String FACEBOOK_REDIRECT_URI="https://localhost:8080/facebookauth2callback";
	
	
	private final TemplateEngine engine = HandlebarsTemplateEngine.create();

	@Override
	public void start(Future<Void> startFuture) throws Exception {

		final Router router = Router.router(vertx);

		router.route().handler(CookieHandler.create());
		router.route().handler(BodyHandler.create());
		router.route().handler(SessionHandler.create(LocalSessionStore.create(vertx)));

		// A user session handler, so that the user is stored in the session between requests
		router.route().handler(UserSessionHandler.create(DatabaseVerticle.authProvider));

		// An auth handler that redirect to login page if user is not stored in the session
		AuthHandler authHandler = RedirectAuthHandler.create(DatabaseVerticle.authProvider, "/login");

		router.route("/").handler(authHandler);

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
							ctx.session().put("uid", userHash);
							
							//Reissue a new auth token and delete the old one 
							LOGGER.info("[handleLogin]Issue a new token.");
							DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.MANAGE_TOKEN.toString()).addHeader("sub_action", UserManagerAction.REISSUE_TOKEN.toString());
							String newClearToken = generateAuthToken();
							JsonObject reissueTokenRequest = new JsonObject()
																.put("token_id", tokenId)
																.put("uid", userHash)
																.put("auth_token", newClearToken)
																.put("valid_to", new Date().getTime()+COOKIE_MAX_AGE*1000);
							
							Message<JsonObject> result = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(),reissueTokenRequest,options,h));
							
							JsonObject returnedUser = result.body().getJsonObject("user");
							Integer newTokenId = result.body().getInteger("token_id");
							
							//creating a new cookie
							LOGGER.info("[handleLogin]Create a new auth token cookie.");
							ctx.addCookie(Cookie.cookie("auth_token",newClearToken+"_"+newTokenId).setMaxAge(COOKIE_MAX_AGE));
							LOGGER.debug("[handleLogin]A cookie is created : {" + ctx.getCookie("auth_token").getName() +":"+ctx.getCookie("auth_token").getValue()+"}");
							
							LOGGER.info("[handleLogin]Setting user into session.");
							ctx.session().put("user", returnedUser);
							
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

		else if (ctx.request().method().equals(HttpMethod.POST)) {

			LOGGER.debug("[handleLogin]Handling login form submit");

			String email = ctx.request().getFormAttribute("login_email");
			String password = ctx.request().getFormAttribute("login_password");

			boolean rememberMe = "remember_me".equals(ctx.request().getFormAttribute("remember_me"));

			if (email == null || password == null) {
				LOGGER.warn("[handleLogin]No email or password provided in the form.");
				ctx.fail(400);
			} else {

				JsonObject authInfo = new JsonObject().put("username", email).put("password", password);
				DatabaseVerticle.authProvider.setAuthenticationQuery(DataBaseQueries.AUTHENTICATE_QUERY_ON_LOCAL_USER).authenticate(authInfo, res -> {
					if (res.succeeded()) {
						// user authenticated
						User user = res.result();
						LOGGER.debug("[handleLogin]User principal: " + user.principal());
						ctx.setUser(user);
						
						if(rememberMe && ctx.getCookie("auth_token")==null){
							
							// login with remember me checked
							
							String clearToken = generateAuthToken();
							
							//sending the auth token to database
							JsonObject rememberMeRequest = new JsonObject()
																.put("email", email)
																.put("auth_token", clearToken)
																.put("valid_to", new Date().getTime()+COOKIE_MAX_AGE*1000);
							
							DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.REMEMBER_ME.toString());
							LOGGER.debug("[handleLogin]Calling user manager LOG_IN_REMEMBER_ME with rememberMeRequest: " + rememberMeRequest);
							
							vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), rememberMeRequest, options,
									
									reply -> {
										
										if (reply.failed()) {
											
											LOGGER.warn("[handleLogin]Remember me request failed with error:  " + reply.cause());
											LOGGER.warn("[handleLogin]Token will not be generated.");
											doRedirect(ctx.request().response(), "/");
										}
										
										else{
											
											JsonObject result = (JsonObject)reply.result().body();
											
											JsonObject returnedUser = result.getJsonObject("user");
											
											String tokenId = result.getString("token_id");
											
											LOGGER.info("[handleLogin]Remember me request successful.");
											LOGGER.debug("[handleLogin]Returned user: " + returnedUser);
											LOGGER.debug("[handleLogin]Returned token id: " + tokenId);
											
											LOGGER.debug("[handleLogin]Creating cookies");
											
											//creating cookie
											ctx.addCookie(Cookie.cookie("auth_token",clearToken+"_"+tokenId).setMaxAge(COOKIE_MAX_AGE));
											LOGGER.debug("[handleLogin]A cookie is created : {" + ctx.getCookie("auth_token").getName() +":"+ctx.getCookie("auth_token").getValue()+"}");
											
											ctx.addCookie(Cookie.cookie("user_hash", returnedUser.getString("UID")).setMaxAge(COOKIE_MAX_AGE));
											LOGGER.debug("[handleLogin]A cookie is created : {" + ctx.getCookie("user_hash").getName() +":"+ctx.getCookie("user_hash").getValue()+"}");
										
											LOGGER.info("[handleLogin]Token has bee stored, cookies are created. User login has been remembered. Setting user into session.");
											
											ctx.session().put("user", returnedUser);
											
											doRedirect(ctx.request().response(), "/");
										}
									}
							);
						
						} else {
							// login without remember me
							ctx.session().put("email", email);
							doRedirect(ctx.request().response(), "/");
						}
					
					} else {
						ctx.fail(403); // Failed login
					}
				});
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
		
		LOGGER.debug("received google call back with Authorization Code.");
		
		
		String googleAuthCode = ctx.request().getParam("code");
		
		JsonObject tokenConfig = new JsonObject()
			    .put("code", googleAuthCode)
			    .put("redirect_uri", "https://localhost:8080/googleoauth2callback");
		
		OAuth2Auth oauth2 = GoogleAuth.create(vertx, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
		
		
		oauth2.getToken(tokenConfig, res -> {
			  if (res.failed()) {
			    LOGGER.error("Access Token Error: " + res.cause().getMessage());
			    doRedirect(ctx.request().response(), "/");
			  } else {
			    // Get the access token object (the authorization code is given from the previous step).
			    AccessToken token = res.result();
			    
			    LOGGER.debug("Received token : " + token.principal());
			    LOGGER.debug("access_token : " + token.principal().getString("access_token"));
			    LOGGER.debug("id_token : " + token.principal().getString("id_token"));
			    
			    JsonObject params = new JsonObject().put("id_token",token.principal().getString("id_token"));

			    // verify id token
			    oauth2.api(HttpMethod.GET, "https://www.googleapis.com/oauth2/v3/tokeninfo?", params, verify ->{
			    	
			    	if(verify.failed())
			    		LOGGER.error(verify.cause().getMessage());
			    	
			    	else{
			    		
			    		LOGGER.debug("Token verification result: " + verify.result());
			    		JsonObject result = verify.result();
			    		
			    		ctx.setUser(token);
			    		String email = result.getString("email");
			    		ctx.session().put("email", email );
			    		
			    		LOGGER.debug("User ID: " + result.getString("sub"));
			    		
			    	}
			    	
			    	doRedirect(ctx.request().response(), "/");
			    });
			    
			    
			    /*
			    try {
					GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(GoogleNetHttpTransport.newTrustedTransport(), JacksonFactory.getDefaultInstance())
							.setAudience(Collections.singletonList(GOOGLE_CLIENT_ID))
							.build();
					
					GoogleIdToken idToken = verifier.verify(token.principal().getString("id_token"));
					
					if (idToken != null) {
						  Payload payload = idToken.getPayload();

						  // Print user identifier
						  String userId = payload.getSubject();
						  LOGGER.debug("User ID: " + userId);

						  // Get profile information from payload
						  String email = payload.getEmail();
						  LOGGER.debug("email:"+email);
						  boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
						  String name = (String) payload.get("name");
						  LOGGER.debug("name:"+name);
						  String pictureUrl = (String) payload.get("picture");
						  LOGGER.debug("pictureUrl:"+pictureUrl);
						  String locale = (String) payload.get("locale");
						  LOGGER.debug("locale:"+locale);
						  String familyName = (String) payload.get("family_name");
						  LOGGER.debug("familyName:"+familyName);
						  String givenName = (String) payload.get("given_name");
						  LOGGER.debug("givenName:"+givenName);
						  // Use or store profile information
						  // ...

						  
						  ctx.session().put("email", email);
						  doRedirect(ctx.request().response(), "/");
						  
						  
						} else {
							LOGGER.error("Invalid ID token.");
						}
					
					
				} catch (GeneralSecurityException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				}
				*/
				
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
		
		LOGGER.debug("received facebook call back with Authorization Code.");
		
		LOGGER.debug(ctx.request().absoluteURI());

		if(ctx.request().getParam("error")!=null){
			
			LOGGER.error("ERROR:" + ctx.request().getParam("error_reason"));
			doRedirect(ctx.response(), "/");
			return;
			
		}
		
		String facebookAuthCode = ctx.request().getParam("code");
		
		JsonObject tokenConfig = new JsonObject()
			    .put("code", facebookAuthCode)
			    .put("redirect_uri", "https://localhost:8080/facebookauth2callback");
		
		OAuth2Auth oauth2 = FacebookAuth.create(vertx, FACEBOOK_APP_ID, FACEBOOK_APP_SECRET);
		
		//Request access token
		oauth2.getToken(tokenConfig, res -> {
			
			  if (res.failed()) {
				  
			    LOGGER.error("Access Token Error: " + res.cause().getMessage());
			    doRedirect(ctx.request().response(), "/");
			    
			  } else {
				  
			    AccessToken token = res.result();
			    
			    LOGGER.debug("Received token : " + token.principal());
			    
			    String accessToken = token.principal().getString("access_token");
			    
			    //Verify access token
			    JsonObject params = new JsonObject().put("input_token",accessToken).put("access_token", FACEBOOK_APP_ID+"|"+FACEBOOK_APP_SECRET);
			    oauth2.api(HttpMethod.GET, "https://graph.facebook.com/debug_token?", params, verify ->{
			    	
			    	if(verify.failed()){
			    		
			    		LOGGER.error(verify.cause().getMessage());
			    		doRedirect(ctx.request().response(), "/");
			    	}
			    		
			    	else{
			    		
			    		LOGGER.debug("Verification result: " + verify.result());
			    		
			    		ctx.setUser(token);
			    		
			    		JsonObject meParams = new JsonObject().put("fields","id,name,email,picture").put("access_token", accessToken);
			    		
			    		oauth2.api(HttpMethod.GET, "https://graph.facebook.com/me?", meParams, me ->{
			    			
			    			if(me.failed()){
			    				LOGGER.error("Retrieving user profile failed : " + me.cause().getMessage());
			    				doRedirect(ctx.request().response(), "/");
			    				return;
			    			}
			    			
			    			else{
			    				String email = me.result().getString("email");
			    				String fullname = me.result().getString("name");
			    				
			    				LOGGER.debug("email:" + email);
			    				ctx.session().put("email", email);
			    				doRedirect(ctx.request().response(), "/");
			    			}
			    		});
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

		LOGGER.debug("received Form Submit: " + ctx.request().absoluteURI());

		LOGGER.debug("received body: " + ctx.getBodyAsString());
		LOGGER.debug("received headers: ");
		ctx.request().headers().forEach(System.out::println);
		
		JsonObject signUpRequest = new JsonObject();

		signUpRequest.put("user_name", ctx.request().getParam("user_name"))
				.put("signup_email", ctx.request().getParam("signup_email"))
				.put("signup_password", ctx.request().getParam("signup_password"));

		LOGGER.debug("Calling user manager sign_up with signUpRequest: " + signUpRequest);

		DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.SIGN_UP.toString());

		vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), signUpRequest, options,
				reply -> {

					if (reply.failed()) {
						LOGGER.error("[handleSignUp] Sign up failed:  " + reply.cause());
						ReplyException exception = (ReplyException) reply.cause();
						ctx.fail(exception.failureCode());
					} else {
						LOGGER.info(reply.result().body().toString());

						JsonObject authInfo = new JsonObject().put("username", ctx.request().getParam("signup_email"))
								.put("password", ctx.request().getParam("signup_password"));

						LOGGER.debug("authInfo: " + authInfo);

						DatabaseVerticle.authProvider.setAuthenticationQuery(DataBaseQueries.AUTHENTICATE_QUERY_ON_LOCAL_USER).authenticate(authInfo, res -> {
							if (res.succeeded()) {
								User user = res.result();
								ctx.setUser(user);
								ctx.session().put("email", user.principal().getString("username"));
								ctx.response().putHeader("location", "/").setStatusCode(303).end();

							} else {
								
								LOGGER.error("[handleSignUp]Login failed after signup : " + res.cause().getMessage());
								ctx.fail(403);
							}
						});

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
		LOGGER.debug("requesting home page /");

		LOGGER.debug("auth user with principal: " + ctx.user().principal());
		

		JsonObject sessionUser = ctx.session().get("user");
				
		LOGGER.debug("session user : " + sessionUser );
		
		// Check if user is stored in session. If not, retrieve user from db
		if(sessionUser==null || sessionUser.isEmpty() ){
			
			JsonObject findUserRequest = new JsonObject();
			
			if(ctx.session().get("uid")!=null)
				findUserRequest.put("uid", (String)ctx.session().get("uid"));
			else if(ctx.session().get("email")!=null)
				findUserRequest.put("email", (String)ctx.session().get("email"));
			else{
				LOGGER.error("no user key is found in the session for retrieving user from db.");
				ctx.fail(403);
				return;
			}
			
			DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.FIND_USER.toString());
			LOGGER.info("[handleHomePage]Calling user manager FIND_USER with findUserRequest: " + findUserRequest);
			vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), findUserRequest, options, reply -> {
	
				if (reply.failed()) {
					LOGGER.error("[handleHomePage]Finding user failed with error:  " + reply.cause());
					ctx.fail((ReplyException)reply.cause());
				} 
				else {
					JsonObject user = (JsonObject)reply.result().body();
					if(user.isEmpty()){
						
						//It means, user is authenticated with login data or cookie, but user is not found in db.  
						//TODO how to handle this scenario?
						renderHandlebarsPage(ctx, "login");
					}
					
					else{
						LOGGER.info("[handleHomePage]Adding user into session");
						ctx.session().put("user",user);
						ctx.put("fullname", user.getString("FULLNAME"));
						ctx.put("page_title", "My Notes - Home");	
						renderHandlebarsPage(ctx, "home");
					}
				}
			});
		}
		
		else {

			ctx.put("fullname", sessionUser.getString("FULLNAME"));
			ctx.put("page_title", "My Notes - Home");	
			renderHandlebarsPage(ctx, "home");
		}
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

		ctx.put("page_title", "My Notes - " + page.substring(0, 1).toUpperCase() + page.substring(1));
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
