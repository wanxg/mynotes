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

		vertx.deployVerticle(new DatabaseVerticle(), context.asyncAssertSuccess());

	}

	@Test
	public void testCreateUser(TestContext context) {

		String email = "eon.wang@gmail.com";
		String password = "12345";

		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_CREATE.toString());

		JsonObject createUserRequest = new JsonObject()
				.put("email", email)
				.put("password", password);
		
		Async async = context.async();
		
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createUserRequest, options, creationReply->{
			
			
			
			if(creationReply.succeeded()){
				LOGGER.info(creationReply.result().body().toString());
			}
			
			else {
				ReplyException exception = (ReplyException) creationReply.cause();
				LOGGER.info(exception.failureCode() + ", " +exception.getMessage());
				
			}
			
			async.complete();
			
		});
		
	}
	
	@Test
	public void testCreateUserProfile(TestContext context) {

		String uid = null;
		String email = "wanxiaolong@gmail.com";
		String username = "Xiaolong";

		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_PROFILE_CREATE.toString());

		JsonObject createUserRequest = new JsonObject()
				.put("uid", uid)
				.put("email", email)
				.put("username", username);
		
		Async async = context.async();
		
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createUserRequest, options, creationReply->{
			
			
			
			if(creationReply.succeeded()){
				LOGGER.info(creationReply.result().body().toString());
			}
			
			else {
				ReplyException exception = (ReplyException) creationReply.cause();
				LOGGER.info(exception.failureCode() + ", " +exception.getMessage());
				
			}
			
			async.complete();
			
		});
		
	}
	
	@Test
	public void findUserProfile(TestContext context){
		
		String userId = "B85E134B8FEE7FFADF31223B3FEFFA7F7039A02978ACAAE3C29893ABE0583935E19CC7B91B5472B0C1FF15DFB2F6976FE80B73937A9F507C124EEE652B34ADE1";

		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_PROFILE_SELECT_BY_USER_ID.toString());;

		JsonObject findUserProfileRequest = new JsonObject().put("userId", userId);
		
		Async async = context.async();

		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findUserProfileRequest, options, reply -> {

			if (reply.succeeded()) {

				JsonObject userProfile = (JsonObject) reply.result().body();
				boolean userProfileFound = !userProfile.isEmpty();
				LOGGER.info("[testFindUserProfile]User profile found? " + userProfileFound);

				LOGGER.info(userProfile.toString());

			}

			else {
				LOGGER.info("[testFindUserProfile]Finding user profile failed : " + reply.cause());
			}
			
			async.complete();
		});
	}
	
	
	
	@Test
	public void testUpdateUserActiveness(TestContext context) {

		String email = "eon.wang@gmail.com";
		Integer activeness = 0;

		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_UPDATE_ACTIVE.toString());

		JsonObject deleteUserRequest = new JsonObject().put("activeness", activeness).put("email", email);

		Async async = context.async();

		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), deleteUserRequest, options, reply -> {

			if (reply.succeeded()) {

				LOGGER.info(reply.result().body().toString());

			}
			else {
				LOGGER.info("[testUpdateUserActiveness]Updating user activeness : " + reply.cause());
			}
			
			async.complete();
		});
		
	}
	
	
	@Test
	public void testFindUser(TestContext context) {

		String by = "username";

		DeliveryOptions options = null;
		String email = "wanxiaolong@gmail.com",
				uid = "A80C4B9D329E5D62CF8F870CFFB220C461E732A17C13FA6D6A590BD259035494D93A4628423F36F48200F8561670EAD0E86AC279884C4895CD7ED4F0057325A4";

		JsonObject findUserRequest = new JsonObject();

		if ("username".equals(by)) {
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_EMAIL.toString());
			findUserRequest.put("email", email);
		}

		else if ("user_id".equals(by)) {
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_UID.toString());
			findUserRequest.put("uid", uid);
		}
		
		final DeliveryOptions opt = options;
		
		
		Async async = context.async();

		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findUserRequest, options, reply -> {

			if (reply.succeeded()) {

				JsonObject user = (JsonObject) reply.result().body();
				boolean userFound = !user.isEmpty();
				LOGGER.info("[testFindUser]User found? " + userFound);

				LOGGER.info(user.toString());

			}

			else {
				LOGGER.info("[testFindUser]Finding user failed : " + reply.cause());
			}
			
			async.complete();
		});
		
		
		/*
		Future<Void> future = Future.future();
		
		future.setHandler(fiberHandler(handler->{
			Message<JsonObject> reply = awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findUserRequest, opt, h));
			
			LOGGER.info(reply.body().toString());

		}));
		
		future.complete();
		*/
		
		
		
	}
	
	
	@Test
	public void testCreateToken(TestContext context) {

		String token = HttpServerVerticle.generateAuthToken();
		String email = "wanxiaolong@gmail.com";

		long validTo = new Date().getTime()+COOKIE_MAX_AGE*1000;
		
		
		java.sql.Timestamp time = new java.sql.Timestamp(validTo);
		
		LOGGER.info(time.toString());
		
		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_CREATE.toString());

		JsonObject createTokenRequest = new JsonObject()
											.put("email", email)
											.put("auth_token", token)
											.put("valid_to", validTo );;
		
		Async async = context.async();
		
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createTokenRequest, options, creationReply->{
			
			if(creationReply.succeeded()){
				LOGGER.info(creationReply.result().body().toString());
			}
			
			else {
				ReplyException exception = (ReplyException) creationReply.cause();
				LOGGER.info(exception.failureCode() + ", " +exception.getMessage());
				
			}
			
			async.complete();
		});
		
	}
	
	
	@Test
	public void testDeleteToken(TestContext context) {

		String tokenId = "10000007";

		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_DELETE.toString());

		JsonObject deleteTokenRequest = new JsonObject().put("token_id", tokenId);

		Async async = context.async();

		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), deleteTokenRequest, options, reply -> {

			if (reply.succeeded()) {

				LOGGER.info(reply.result().body().toString());

			}

			else {
				LOGGER.info("[testDeleteToken]Deleting token failed : " + reply.cause());
			}
			
			async.complete();
		});
		
	}
	
	
	@After
	public void tearDown(TestContext context) {
	    vertx.close(context.asyncAssertSuccess());
	}

}
