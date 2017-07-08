package com.wanxg.mynotes.core;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.EventBusAddress;
import com.wanxg.mynotes.FailureCode;
import com.wanxg.mynotes.WarningCode;
import com.wanxg.mynotes.database.DatabaseOperation;
import com.wanxg.mynotes.database.DatabaseVerticle;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.eventbus.ReplyException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;

public class UserManagerVerticle extends AbstractVerticle {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(UserManagerVerticle.class);
	
	@Override
	public void start(Future<Void> startFuture) throws Exception {
		
		LOGGER.info("Starting UserManagerVerticle ...");
		
		vertx.eventBus().consumer(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), this::distributeAction);
		startFuture.complete();
	}
	
	
	private void distributeAction(Message<JsonObject> message){
		
		if(!message.headers().contains("user"))
			message.fail(FailureCode.NO_USER_KEY_SPECIFIED.getCode(), "No user manager key specified in the msg header.");
		
		
		UserManagerAction action = UserManagerAction.valueOf(message.headers().get("user"));
		
		DeliveryOptions options;
		JsonObject userSelectRequest;
		String username, userHash, clearToken,tokenId;
		
		switch(action){
			
			case SIGN_UP:
				
				options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERNAME.toString());
				userSelectRequest = new JsonObject().put("username", message.body().getString("signup_email"));
				
				vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), userSelectRequest,options,reply->{
					
					if(reply.succeeded()){
						
						JsonObject body = (JsonObject)reply.result().body();
						boolean userExists = !body.isEmpty();
						LOGGER.debug("user exists? " + userExists);
						
						if(!userExists){
							
							DeliveryOptions opt = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_CREATE.toString());
							JsonObject createUserRequest = new JsonObject()
									.put("username", message.body().getString("signup_email"))
									.put("fullname", message.body().getString("full_name"))
									.put("password", message.body().getString("signup_password"));
							
							
							vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createUserRequest, opt, creationReply->{
								
								if(creationReply.succeeded()){
									message.reply(creationReply.result().body().toString());
								}
								
								else {
									ReplyException exception = (ReplyException) creationReply.cause();
									message.fail(exception.failureCode(), exception.getMessage());
								}
							});
						}
						
						else{
							LOGGER.error("[SIGN_UP]The Provided email is already registered.");
							message.fail(FailureCode.EMAIL_ALREADY_EXISTS.getCode(), "The Provided email is already registered.");
						}
					}
					
					else
						message.fail(FailureCode.EVENTBUS_ERROR.getCode(), reply.cause().getMessage());
				});
				
				break;
			
				
			case LOG_IN_REMEMBER_ME:
				
				
				username = message.body().getString("username");
				clearToken = message.body().getString("auth_token");
				
				options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_TOKEN_CREATE.toString());
				JsonObject createTokenRequest = new JsonObject();
				createTokenRequest.put("username", username).put("auth_token", clearToken);
				
				LOGGER.debug("[LOG_IN_REMEMBER_ME]Creating token with tokenRequest: " + createTokenRequest);
				
				vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createTokenRequest, options, reply -> {
							
					if(reply.succeeded()){
						
						String returnedTokenId = reply.result().body().toString();
						LOGGER.debug("[LOG_IN_REMEMBER_ME]Token has been created and stored. Retrieving user hash.");
						DeliveryOptions opt = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERNAME.toString());
						JsonObject userSelectReq = new JsonObject().put("username", username);
						
						vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), userSelectReq,opt,query->{
							
							if(query.succeeded()){
								JsonObject body = (JsonObject)query.result().body();
								String userId = body.getString("USER_ID");
								LOGGER.debug("[LOG_IN_REMEMBER_ME]User hash has been retrieved : " + userId);
								message.reply(new JsonObject().put("user_hash", userId).put("token_id", returnedTokenId));
							}
							
							else
								message.fail(FailureCode.EVENTBUS_ERROR.getCode(), reply.cause().getMessage());
							
						});
					}
					else{
						LOGGER.warn("[LOG_IN_REMEMBER_ME]Token creation failed in DB." + reply.cause());
						message.fail(WarningCode.TOKEN_CREATION_FAILED.getCode(), "Token creation failed.");
					}
				});
				
				break;
			
			case LOG_IN_WITH_COOKIE:
				
				userHash = message.body().getString("user_hash");
				clearToken = message.body().getString("clear_token");
				tokenId= message.body().getString("token_id");
				
				options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_SELECT_BY_USERID_TOKENID.toString());
				JsonObject findTokenRequest = new JsonObject();
				findTokenRequest.put("user_id", userHash).put("token_id", tokenId);
				
				LOGGER.debug("[LOG_IN_WITH_COOKIE]Searching for token(s) with user hash" + findTokenRequest);
				
				vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findTokenRequest, options, reply -> {
					
					if(reply.succeeded()){
						
						JsonObject result = (JsonObject)reply.result().body();
						
						if(result.isEmpty()){
							
							LOGGER.warn("[LOG_IN_WITH_COOKIE]Token not found.");
							message.fail(WarningCode.TOKEN_NOT_FOUND.getCode(), "Token not found");
						}
						
						
						LOGGER.debug("[LOG_IN_WITH_COOKIE]Result: " + result.toString());
							
						String hashedToken = result.getString("TOKEN");
							
						JsonObject authInfo = new JsonObject().put("username", tokenId).put("password",clearToken);
							
						DatabaseVerticle.authProvider.setAuthenticationQuery(DatabaseVerticle.AUTHENTICATE_QUERY_FOR_TOKEN).authenticate(authInfo, res -> {
								if (res.succeeded()) {
									// user authenticated
									User user = res.result();
									LOGGER.debug("[LOG_IN_WITH_COOKIE]User authenticated.");
									LOGGER.debug("[LOG_IN_WITH_COOKIE]User principal: " + user.principal());
								}
								else{
									LOGGER.debug("[LOG_IN_WITH_COOKIE]Not the correct token : " + hashedToken);
								}
						});
							
					}
					
					else{
						message.fail(FailureCode.EVENTBUS_ERROR.getCode(), reply.cause().getMessage());
					}
				});
				
				break;
				
			default:
				
				message.fail(FailureCode.BAD_USER_ACTION.getCode(), "Bad user action: " + action);
				
		}
	}

}
