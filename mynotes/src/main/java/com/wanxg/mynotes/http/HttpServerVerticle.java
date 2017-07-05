package com.wanxg.mynotes.http;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.EventBusAddress;
import com.wanxg.mynotes.core.UserManagerAction;
import com.wanxg.mynotes.database.DatabaseVerticle;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.ReplyException;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.AuthHandler;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.handler.FaviconHandler;
import io.vertx.ext.web.handler.FormLoginHandler;
import io.vertx.ext.web.handler.RedirectAuthHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.handler.StaticHandler;
import io.vertx.ext.web.handler.UserSessionHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;
import io.vertx.ext.web.templ.HandlebarsTemplateEngine;
import io.vertx.ext.web.templ.TemplateEngine;

public class HttpServerVerticle extends AbstractVerticle {

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpServerVerticle.class);
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
		
		// handle login post, if user is authenticated, direct to root / home page
		router.post("/login").handler(FormLoginHandler.create(DatabaseVerticle.authProvider).setPasswordParam("login_password")
				.setUsernameParam("login_email").setDirectLoggedInOKURL("/"));

		// handle login get
		router.get("/login").handler(this::handleLogin);
		
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
		//router.get("/templates/*").handler(handler);

		// route for static resources
		router.route().handler(StaticHandler.create().setCachingEnabled(false));

		router.route().handler(FaviconHandler.create("webroot/pic/favicon.ico"));
		
		router.route().failureHandler(this::handleFailure);
		
		
		LOGGER.info("Starting a HTTP web server on port 8080");
		vertx.createHttpServer(new HttpServerOptions().setKeyStoreOptions(new JksOptions()
			      .setPath("server-keystore.jks")
			      .setPassword("secret"))
			      .setSsl(true)
			    ).requestHandler(router::accept).listen(8080, ar -> {
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
	 *  Handle HTTP GET for log in
	 * @param ctx
	 */
	private void handleLogin(RoutingContext ctx){
		LOGGER.debug("logging in ...");
		
		boolean isAuthenticated = ctx.user() != null;
		
		if(isAuthenticated)
			//ctx.reroute(HttpMethod.GET, "/");
			ctx.response().putHeader("location", "/").setStatusCode(302).end();
		else{
			renderHandlebarsPage(ctx,"login");
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
		
		signUpRequest
			.put("full_name", ctx.request().getParam("full_name"))
			.put("signup_email", ctx.request().getParam("signup_email"))
			.put("signup_password", ctx.request().getParam("signup_password"));

		LOGGER.debug("signUpRequest: " + signUpRequest );
		
		DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.SIGN_UP.toString());
		
		vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), signUpRequest, options, reply-> {
			
			if(reply.failed()){
				LOGGER.error("[handleSignUp] Sign up failed with error:  " + reply.cause());
				ReplyException exception = (ReplyException)reply.cause();
				ctx.fail(exception.failureCode());
			}
			else{
				LOGGER.info(reply.result().body().toString());
				
				JsonObject authInfo = new JsonObject().put("username", ctx.request().getParam("signup_email")).put("password", ctx.request().getParam("signup_password"));
				
				LOGGER.debug("authInfo: " + authInfo);
				
				DatabaseVerticle.authProvider.authenticate(authInfo, res -> {
					  if (res.succeeded()) {
					    User user = res.result();
					    ctx.setUser(user);
					    ctx.put("full_name", ctx.request().getParam("full_name"));
					    //ctx.reroute(HttpMethod.GET, "/");
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
		ctx.clearUser();
		// Redirect back to the login page
		ctx.response().putHeader("location", "/").setStatusCode(302).end();
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

		//ctx.put("full_name", "Xiaolong");

		ctx.put("page_title", "My Notes - Home");
		renderHandlebarsPage(ctx,"home");
	}
	
	
	
	
	/**
	 *  Handle HTTP request failure for different status codes
	 * 
	 * @param ctx
	 */
	private void handleFailure(RoutingContext ctx){
		
		LOGGER.debug("status code: " + ctx.statusCode());
		LOGGER.debug("failure: " + ctx.failure());
		LOGGER.debug("path:" + ctx.request().path());
		
		switch (ctx.statusCode()){
		
			case 404: 
				
				ctx.put("error_message", "Requested resource doesn't exist.");
				renderHandlebarsPage(ctx,"error");
				break;
			
			case 403:
				
				ctx.put("login_failed", true);
				renderHandlebarsPage(ctx,"login");
				break;
				
				
			case 803:
				
				ctx.put("signup_failed", true);
				renderHandlebarsPage(ctx,"login");
				break;
			
			default:
				
				ctx.put("error_message", ctx.failure());
				renderHandlebarsPage(ctx,"error");
				
		}
	}
	
	
	/**
	 * call handlebars template engine to render login.hbs
	 * 
	 * @param ctx
	 */
	private void renderHandlebarsPage(RoutingContext ctx,String page){
		
		ctx.put("page_title", "My Notes - " + page.substring(0,1).toUpperCase() + page.substring(1));
		engine.render(ctx, "templates/", "_"+page+".hbs", res -> {
			if (res.succeeded()) {
				ctx.response().putHeader("Content-Type", "text/html");
				ctx.response().end(res.result());
			} else {
				ctx.fail(res.cause());
			}
		});
	}
	
	
	
	
}
