package com.wanxg.mynotes.http;

import com.wanxg.mynotes.EventBusAddress;
import com.wanxg.mynotes.core.UserManagerAction;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.shiro.PropertiesProviderConstants;
import io.vertx.ext.auth.shiro.ShiroAuth;
import io.vertx.ext.auth.shiro.ShiroAuthOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.handler.FaviconHandler;
import io.vertx.ext.web.handler.FormLoginHandler;
import io.vertx.ext.web.handler.RedirectAuthHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.handler.StaticHandler;
import io.vertx.ext.web.handler.TemplateHandler;
import io.vertx.ext.web.handler.UserSessionHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;
import io.vertx.ext.web.templ.HandlebarsTemplateEngine;
import io.vertx.ext.web.templ.TemplateEngine;

public class HttpServerVerticle extends AbstractVerticle {

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpServerVerticle.class);

	private final TemplateEngine engine = HandlebarsTemplateEngine.create();
	private final TemplateHandler handler = TemplateHandler.create(engine);
	
	@Override
	public void start(Future<Void> startFuture) throws Exception {

		final Router router = Router.router(vertx);

		router.route().handler(CookieHandler.create());
		router.route().handler(BodyHandler.create());
		router.route().handler(SessionHandler.create(LocalSessionStore.create(vertx)));

		// Simple auth service which uses a properties file for user/role info

		JsonObject config = new JsonObject();
		config.put(PropertiesProviderConstants.PROPERTIES_PROPS_PATH_FIELD, "classpath:users.properties");
		AuthProvider authProvider = ShiroAuth.create(vertx, new ShiroAuthOptions().setConfig(config));

		// A user session handler, so that the user is stored in the session
		// between requests
		router.route().handler(UserSessionHandler.create(authProvider));

		/*
		 * A root route router.get("/").handler(ctx -> { ctx.response()
		 * .putHeader("content-type","text/html")
		 * .sendFile("webroot/index.html"); });
		 */

		// handle login, if user is authenticated, direct to /home
		router.route("/login").handler(FormLoginHandler.create(authProvider).setPasswordParam("login_password")
				.setUsernameParam("login_email").setDirectLoggedInOKURL("/home"));

		// handle logout, clear the authentication and direct to login page
		router.route("/logout").handler(this::logOutHandler);

		// handle sign up
		router.post("/signup").handler(this::signUpHandler);

		// Any requests to URI starting '/templates/' require login
		router.route("/templates/*").handler(RedirectAuthHandler.create(authProvider, "/"));

		router.route("/templates/*").handler(StaticHandler.create().setCachingEnabled(false));

		// router.get("/templates/*").handler(handler);

		// handle home page after login

		router.get("/home").handler(this::homePageHandler);

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

		router.route().handler(FaviconHandler.create("/pic/favicon.ico"));
		
		
		
		LOGGER.info("Starting a HTTP web server on port 8080");
		vertx.createHttpServer().requestHandler(router::accept).listen(8080, ar -> {
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
	 * Handle sign up
	 * 
	 * @param ctx
	 */
	private void signUpHandler(RoutingContext ctx) {

		System.out.println("I got the form submit: " + ctx.request().absoluteURI());

		JsonObject signUpRequest = new JsonObject();
		
		signUpRequest
			.put("fullName", ctx.request().getParam("fullName"))
			.put("signup_email", ctx.request().getParam("signup_email"))
			.put("signup_password", ctx.request().getParam("signup_password"));

		System.out.println("fullName,email,password: " + signUpRequest);
		
		DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.SIGN_UP.toString());
		
		vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), signUpRequest, options, reply-> {
			
			if(reply.failed()){
				LOGGER.error("[signUpHandler] Sign up failed with error:  " + reply.cause());
				ctx.fail(reply.cause());
			}
			else{
				LOGGER.info(reply.result().body());
			}
			
		});

		ctx.reroute(HttpMethod.GET, "/home");

		// ctx.response().putHeader("location",
		// "/home").setStatusCode(302).end();

	}
	
	/**
	 * Handle log out
	 * 
	 * @param ctx
	 */
	private void logOutHandler(RoutingContext ctx) {
		ctx.clearUser();
		// Redirect back to the index page
		ctx.response().putHeader("location", "/").setStatusCode(302).end();
	}

	/**
	 * Handle HTTP GET on /home
	 * 
	 * @param ctx
	 */
	
	private void homePageHandler(RoutingContext ctx) {
		System.out.println("requesting home");
		User user = ctx.user();

		System.out.println("user: " + user);

		boolean isAuthenticated = user != null;
		ctx.put("fullName", "Xiaolong");

		if (isAuthenticated) {
			engine.render(ctx, "webroot/templates/", "_home.hbs", res -> {

				if (res.succeeded()) {
					ctx.response().end(res.result());
				} else {
					ctx.fail(res.cause());
				}
			});
		}

		else {
			ctx.response().putHeader("location", "/").setStatusCode(302).end();
		}
	}

}
