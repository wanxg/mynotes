package com.wanxg.mynotes.http;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.EventBusAddress;
import com.wanxg.mynotes.core.UserManagerAction;
import com.wanxg.mynotes.database.DatabaseVerticle;

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
	private static final long COOKIE_MAX_AGE = 60*60*24*7;
	
	
	private final TemplateEngine engine = HandlebarsTemplateEngine.create();

	@Override
	public void start(Future<Void> startFuture) throws Exception {

		final Router router = Router.router(vertx);

		router.route().handler(CookieHandler.create());
		router.route().handler(BodyHandler.create());
		router.route().handler(SessionHandler.create(LocalSessionStore.create(vertx)));

		// A user session handler, so that the user is stored in the session
		// between requests
		router.route().handler(UserSessionHandler.create(DatabaseVerticle.authProvider));

		// An auth handler that redirect to login page if user is not stored in
		// the session
		AuthHandler authHandler = RedirectAuthHandler.create(DatabaseVerticle.authProvider, "/login");

		router.route("/").handler(authHandler);

		// handle login post, if user is authenticated, direct to root / home
		// page
		// router.post("/login").handler(FormLoginHandler.create(DatabaseVerticle.authProvider).setPasswordParam("login_password")
		// .setUsernameParam("login_email").setDirectLoggedInOKURL("/"));

		router.route("/login").handler(this::handleLogin);

		// handle sign up
		router.post("/signup").handler(this::handleSignUp);

		// handle logout, clear the authentication and direct to login page
		router.route("/logout").handler(this::handleLogout);

		// handle home page after login
		router.get("/").handler(this::handleHomePage);

		// A route for user information
		router.get("/user/").handler(ctx -> {

			String fullName = ctx.request().getParam("fullName");
			String eMail = ctx.request().getParam("eMail");
			System.out.println("Full name: " + fullName + ", eMail: " + eMail);

		});

		// route for handlebars templates
		// router.get("/templates/*").handler(handler);

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
				// ctx.reroute(HttpMethod.GET, "/");
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
					
					/*
					JsonObject authInfo = new JsonObject().put("user_hash", userHash).put("clear_token", clearToken).put("token_id", tokenId);
					DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.LOG_IN_WITH_COOKIE.toString());
					LOGGER.debug("[handleLogin]Calling user manager LOG_IN_WITH_COOKIE with auth info: " + authInfo);
					vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), authInfo, options,

							reply -> {
								
								if (reply.failed()) {
									LOGGER.warn("[handleLogin]Automatic login with cookie failed with error:  " + reply.cause());
									tokenCookie.setMaxAge(0);
									userHashCookie.setMaxAge(0);
									renderHandlebarsPage(ctx, "login");
								}
								else{
									String result = reply.result().body().toString();
									doRedirect(ctx.request().response(), "/");
								}
							}
					);
					*/
					
					JsonObject authInfo = new JsonObject().put("username", tokenId).put("password", clearToken);
					DatabaseVerticle.authProvider.setAuthenticationQuery(DatabaseVerticle.AUTHENTICATE_QUERY_FOR_TOKEN).authenticate(authInfo, res -> {
						if (res.succeeded()) {
							// user authenticated
							User user = res.result();
							LOGGER.debug("[handleLogin]Automatic login with cookies successful.");
							LOGGER.debug("[handleLogin]AutomUser principal: " + user.principal());
							ctx.setUser(user);
							doRedirect(ctx.request().response(), "/");
						}
						else{
							LOGGER.debug("[handleLogin]Automatic login with cookies failed. Removing cookies");
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
							
							String authToken = this.generateAuthToken();
							
							//sending the auth token to database
							JsonObject rememberMeRequest = new JsonObject().put("username", email).put("auth_token", authToken);
							DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.LOG_IN_REMEMBER_ME.toString());
							LOGGER.debug("[handleLogin]Calling user manager LOG_IN_REMEMBER_ME with rememberMeRequest: " + rememberMeRequest);
							
							vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), rememberMeRequest, options,
									
									reply -> {
										
										if (reply.failed()) {
											
											LOGGER.warn("[handleLogin]Remember me request failed with error:  " + reply.cause());
											doRedirect(ctx.request().response(), "/");
										}
										
										else{
											
											JsonObject result = (JsonObject)reply.result().body();
											
											String userHash = result.getString("user_hash");
											String tokenId = result.getString("token_id");
											
											LOGGER.info("[handleLogin]Remember me request successful, returned user hash: " + userHash);
											LOGGER.debug("[handleLogin]Creating cookies");
											
											//creating cookies
											ctx.addCookie(Cookie.cookie("auth_token",authToken+"_"+tokenId).setMaxAge(COOKIE_MAX_AGE));
											LOGGER.debug("[handleLogin]A cookie is created : {" + ctx.getCookie("auth_token").getName() +":"+ctx.getCookie("auth_token").getValue()+"}");
											
											ctx.addCookie(Cookie.cookie("user_hash", userHash).setMaxAge(COOKIE_MAX_AGE));
											LOGGER.debug("[handleLogin]A cookie is created : {" + ctx.getCookie("user_hash").getName() +":"+ctx.getCookie("user_hash").getValue()+"}");
										
											LOGGER.info("[handleLogin]Token has bee stored, cookies are created. User login has been remembered.");
											
											doRedirect(ctx.request().response(), "/");
										}
									}
							);
						}
						
						else
							doRedirect(ctx.request().response(), "/");
						
						
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
								ctx.put("full_name", ctx.request().getParam("full_name"));
								// ctx.reroute(HttpMethod.GET, "/");
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
		
		Cookie authCookie = ctx.getCookie("auth_token");
		
		if(authCookie!=null){
			LOGGER.debug("Cookie:" + authCookie);
			authCookie.setMaxAge(0);
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

		User user = ctx.user();
		LOGGER.debug("user: " + user);

		//ctx.put("username", user.principal().getValue("username"));

		ctx.put("page_title", "My Notes - Home");
		renderHandlebarsPage(ctx, "home");
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
	 *  Generate authentication token for cookie 
	 */
	
	private String generateAuthToken(){
		SecureRandom random = new SecureRandom();
		return new BigInteger(130, random).toString(32);
	}

}
