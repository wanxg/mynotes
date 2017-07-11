package com.wanxg.mynotes.http;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.core.UserManagerAction;
import com.wanxg.mynotes.database.DatabaseOperation;
import com.wanxg.mynotes.database.DatabaseVerticle;
import com.wanxg.mynotes.util.EventBusAddress;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.ReplyException;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jdbc.JDBCAuth;
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
					DatabaseVerticle.authProvider.setAuthenticationQuery(DatabaseVerticle.AUTHENTICATE_QUERY_FOR_TOKEN).authenticate(authInfo, res -> {
						if (res.succeeded()) {
							// user authenticated
							User user = res.result();
							LOGGER.info("[handleLogin]Automatic login with cookies successful.");
							LOGGER.debug("[handleLogin]User principal: " + user.principal());
							ctx.setUser(user);
							ctx.session().put("user_id", userHash);
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
					});
					
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
				LOGGER.warn("[handleLogin]No username or password provided in the form.");
				ctx.fail(400);
			} else {

				JsonObject authInfo = new JsonObject().put("username", email).put("password", password);
				DatabaseVerticle.authProvider.setAuthenticationQuery(JDBCAuth.DEFAULT_AUTHENTICATE_QUERY).authenticate(authInfo, res -> {
					if (res.succeeded()) {
						// user authenticated
						User user = res.result();
						LOGGER.debug("[handleLogin]User principal: " + user.principal());
						ctx.setUser(user);
						
						if(rememberMe && ctx.getCookie("auth_token")==null){
							
							String clearToken = generateAuthToken();
							
							//sending the auth token to database
							JsonObject rememberMeRequest = new JsonObject()
																.put("username", email)
																.put("auth_token", clearToken)
																.put("valid_to", new Date().getTime()+COOKIE_MAX_AGE*1000);
							
							DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.LOG_IN_REMEMBER_ME.toString());
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
											
											ctx.addCookie(Cookie.cookie("user_hash", returnedUser.getString("USER_ID")).setMaxAge(COOKIE_MAX_AGE));
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
	 * Handle HTTP POST for sign up
	 * 
	 * @param ctx
	 */
	private void handleSignUp(RoutingContext ctx) {

		LOGGER.debug("retrieved Form Submit: " + ctx.request().absoluteURI());

		JsonObject signUpRequest = new JsonObject();

		signUpRequest.put("full_name", ctx.request().getParam("full_name"))
				.put("signup_email", ctx.request().getParam("signup_email"))
				.put("signup_password", ctx.request().getParam("signup_password"));

		LOGGER.debug("Calling user manager sign_up with signUpRequest: " + signUpRequest);

		DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.SIGN_UP.toString());

		vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), signUpRequest, options,
				reply -> {

					if (reply.failed()) {
						LOGGER.error("[handleSignUp] Sign up failed with error:  " + reply.cause());
						ReplyException exception = (ReplyException) reply.cause();
						ctx.fail(exception.failureCode());
					} else {
						LOGGER.info(reply.result().body().toString());

						JsonObject authInfo = new JsonObject().put("username", ctx.request().getParam("signup_email"))
								.put("password", ctx.request().getParam("signup_password"));

						LOGGER.debug("authInfo: " + authInfo);

						DatabaseVerticle.authProvider.setAuthenticationQuery(JDBCAuth.DEFAULT_AUTHENTICATE_QUERY).authenticate(authInfo, res -> {
							if (res.succeeded()) {
								User user = res.result();
								ctx.setUser(user);
								ctx.session().put("email", user.principal().getString("username"));
								ctx.response().putHeader("location", "/").setStatusCode(303).end();

							} else {
								LOGGER.error(res.cause().getMessage());
								ctx.fail(res.cause());
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
			
			if(ctx.session().get("user_id")!=null)
				findUserRequest.put("user_id", (String)ctx.session().get("user_id"));
			else if(ctx.session().get("email")!=null)
				findUserRequest.put("username", (String)ctx.session().get("email"));
			else{
				LOGGER.error("no user key is found in the session for retrieving db from db.");
				ctx.fail(403);
				return;
			}
			
			DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.FIND_USER.toString());
			LOGGER.info("[handleHomePage]Calling user manager FIND_USER with findUserRequest: " + findUserRequest);
			vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), findUserRequest, options, reply -> {
	
				if (reply.failed()) {
					LOGGER.error("[handleHomePage]Finding user failed with error:  " + reply.cause());
					ctx.fail(((ReplyException)reply.cause()).failureCode());
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

		switch (ctx.statusCode()) {

		case 404:

			ctx.put("error_message", "Requested resource doesn't exist.");
			renderHandlebarsPage(ctx, "error");
			break;

		case 403:

			ctx.put("login_failed", true);
			renderHandlebarsPage(ctx, "login");
			break;

		case 803:

			ctx.put("signup_failed", true);
			renderHandlebarsPage(ctx, "login");
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
	 *  to delete the token with id
	 * 
	 */
	
	private void deleteToken(String tokenId){

		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_DELETE.toString());
		JsonObject deleteTokenRequest = new JsonObject().put("token_id", tokenId);
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), deleteTokenRequest, options, reply -> {
			
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
