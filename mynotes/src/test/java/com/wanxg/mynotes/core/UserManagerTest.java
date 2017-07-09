package com.wanxg.mynotes.core;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.EventBusAddress;
import com.wanxg.mynotes.database.DatabaseVerticle;
import com.wanxg.mynotes.http.HttpServerVerticle;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

@RunWith(VertxUnitRunner.class)
public class UserManagerTest {

	private Vertx vertx;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(UserManagerTest.class);

	@Before
	public void prepare(TestContext context) throws InterruptedException {

		vertx = Vertx.vertx();

		Async async = context.async();
		
		Future<String> databaseDeployment = Future.future();

		vertx.deployVerticle(new DatabaseVerticle(), databaseDeployment.completer());

		databaseDeployment.compose(id -> {

			Future<String> userManagerDeployment = Future.future();
			
			vertx.deployVerticle(new UserManagerVerticle(), userManagerDeployment.completer());
			
			return userManagerDeployment;

		}).setHandler(ar -> {

			if (ar.succeeded()) {
				LOGGER.info("Ready for running tests.");
				//context.asyncAssertSuccess();
				async.complete();
			} 
			
			else
				context.fail();
		});
		
		async.await();

	}

	@Test
	public void testSignup(TestContext context) {
		
		String email = "luna.wan@gmail.com";
		String fullname = "Luna";
		String password = "12345";
		
		
		JsonObject signUpRequest = new JsonObject();

		signUpRequest.put("full_name", fullname)
				.put("signup_email", email)
				.put("signup_password", password);

		DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.SIGN_UP.toString());
		
		Async async = context.async();
		
		vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), signUpRequest, options,
				reply -> {

					async.complete();
					
					if (reply.failed()) {
						LOGGER.debug("[testSignup] Sign up failed with error:  " + reply.cause());
					} else {
						LOGGER.debug(reply.result().body().toString());

					}

				});
		
		async.await();
	}
	
	@Test
	public void testLoginRememberMe(TestContext context) {
		
		
		String email = "luna.wan@gmail.com";
		String token = HttpServerVerticle.generateAuthToken();
		
		JsonObject rememberMeRequest = new JsonObject().put("username", email).put("auth_token", token);
		DeliveryOptions options = new DeliveryOptions().addHeader("user", UserManagerAction.LOG_IN_REMEMBER_ME.toString());
		LOGGER.debug("[testLoginRememberMe]Calling user manager LOG_IN_REMEMBER_ME with rememberMeRequest: " + rememberMeRequest);
		
		
		Async async = context.async();
		
		vertx.eventBus().send(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), rememberMeRequest, options,
				
				reply -> {

					async.complete();
					
					if (reply.failed()) {
						System.out.println("[testLoginRememberMe] Sign up failed with error:  " + reply.cause());
					} 
					
					else {
						
						JsonObject result = (JsonObject)reply.result().body();
						String userHash = result.getString("user_hash");
						String tokenId = result.getString("token_id");
						
						LOGGER.info("[testLoginRememberMe]Remember me request successful, returned user hash: " + userHash);
						LOGGER.info("[testLoginRememberMe]returned token id: " + tokenId);

					}

				});
		
		async.await();
	}
	
	
	@After
	public void tearDown(TestContext context) {
	    vertx.close(context.asyncAssertSuccess());
	}

}
