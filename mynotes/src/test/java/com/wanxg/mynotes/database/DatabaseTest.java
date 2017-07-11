package com.wanxg.mynotes.database;

import java.util.Date;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.http.HttpServerVerticle;
import com.wanxg.mynotes.util.EventBusAddress;

import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.ReplyException;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

@RunWith(VertxUnitRunner.class)
public class DatabaseTest {

	private Vertx vertx;
	private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseTest.class);
	private static final long COOKIE_MAX_AGE = 60*60*24*1;
	
	
	@Before
	public void prepare(TestContext context) throws InterruptedException {

		vertx = Vertx.vertx();

		vertx.deployVerticle(new DatabaseVerticle(), context.asyncAssertSuccess(id -> {

		}));

	}

	@Test
	public void testCreateUser(TestContext context) {

		String email = "eon.wang@gmail.com";
		String fullname = "Eon";
		String password = "12345";

		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_CREATE.toString());

		JsonObject createUserRequest = new JsonObject()
				.put("username", email)
				.put("fullname", fullname)
				.put("password", password);
		
		Async async = context.async();
		
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createUserRequest, options, creationReply->{
			
			async.complete();
			
			if(creationReply.succeeded()){
				LOGGER.info(creationReply.result().body().toString());
			}
			
			else {
				ReplyException exception = (ReplyException) creationReply.cause();
				LOGGER.info(exception.failureCode() + ", " +exception.getMessage());
				
			}
		});
		
		async.await();
	}
	
	
	@Test
	public void testUpdateUserActiveness(TestContext context) {

		String username = "eon.wang@gmail.com";
		Integer activeness = 1;

		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_UPDATE_ACTIVE.toString());

		JsonObject deleteUserRequest = new JsonObject().put("activeness", activeness).put("username", username);

		Async async = context.async();

		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), deleteUserRequest, options, reply -> {

			async.complete();
			
			if (reply.succeeded()) {

				LOGGER.info(reply.result().body().toString());

			}
			else {
				LOGGER.info("[testUpdateUserActiveness]Updating user activeness : " + reply.cause());
			}
		});
		
		async.await();
	}
	
	
	@Test
	public void testFindUser(TestContext context) {

		String by = "username";

		DeliveryOptions options = null;
		String username = "wanxiaolong@gmail.com",
				userId = "A80C4B9D329E5D62CF8F870CFFB220C461E732A17C13FA6D6A590BD259035494D93A4628423F36F48200F8561670EAD0E86AC279884C4895CD7ED4F0057325A4";

		JsonObject findUserRequest = new JsonObject();

		if ("username".equals(by)) {
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERNAME.toString());
			findUserRequest.put("username", username);
		}

		else if ("user_id".equals(by)) {
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERID.toString());
			findUserRequest.put("user_id", userId);
		}
		
		Async async = context.async();

		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findUserRequest, options, reply -> {

			async.complete();
			
			if (reply.succeeded()) {

				JsonObject user = (JsonObject) reply.result().body();
				boolean userFound = !user.isEmpty();
				LOGGER.info("[testFindUser]User found? " + userFound);

				LOGGER.info(user.toString());

			}

			else {
				LOGGER.info("[testFindUser]Finding user failed : " + reply.cause());
			}
		});
		
		async.await();
	}
	
	
	@Test
	public void testCreateToken(TestContext context) {

		String token = HttpServerVerticle.generateAuthToken();
		String username = "wanxiaolong@gmail.com";

		long validTo = new Date().getTime()+COOKIE_MAX_AGE*1000;
		
		
		java.sql.Timestamp time = new java.sql.Timestamp(validTo);
		
		LOGGER.info(time.toString());
		
		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_CREATE.toString());

		JsonObject createTokenRequest = new JsonObject()
											.put("username", username)
											.put("auth_token", token)
											.put("valid_to", validTo );;
		
		Async async = context.async();
		
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createTokenRequest, options, creationReply->{
			
			async.complete();
			
			if(creationReply.succeeded()){
				LOGGER.info(creationReply.result().body().toString());
			}
			
			else {
				ReplyException exception = (ReplyException) creationReply.cause();
				LOGGER.info(exception.failureCode() + ", " +exception.getMessage());
				
			}
		});
		
		async.await();
	}
	
	
	@Test
	public void testDeleteToken(TestContext context) {

		String tokenId = "10000007";

		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_DELETE.toString());

		JsonObject deleteTokenRequest = new JsonObject().put("token_id", tokenId);

		Async async = context.async();

		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), deleteTokenRequest, options, reply -> {

			async.complete();
			
			if (reply.succeeded()) {

				LOGGER.info(reply.result().body().toString());

			}

			else {
				LOGGER.info("[testDeleteToken]Deleting token failed : " + reply.cause());
			}
		});
		
		async.await();
	}
	
	

	
	
	@After
	public void tearDown(TestContext context) {
	    vertx.close(context.asyncAssertSuccess());
	}

}
