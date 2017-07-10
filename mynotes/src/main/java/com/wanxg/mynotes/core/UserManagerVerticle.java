package com.wanxg.mynotes.core;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.database.DatabaseOperation;
import com.wanxg.mynotes.util.EventBusAddress;
import com.wanxg.mynotes.util.FailureCode;
import com.wanxg.mynotes.util.WarningCode;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.eventbus.ReplyException;
import io.vertx.core.json.JsonObject;

public class UserManagerVerticle extends AbstractVerticle {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(UserManagerVerticle.class);
	
	@Override
	public void start(Future<Void> startFuture) throws Exception {
		
		LOGGER.info("Starting UserManagerVerticle ...");
		
		LOGGER.info("Listening to " + EventBusAddress.USER_MANAGER_QUEUE_ADDRESS + " on event bus ...");
		vertx.eventBus().consumer(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), this::distributeAction);
		startFuture.complete();
	}
	
	
	private void distributeAction(Message<JsonObject> message){
		
		if(!message.headers().contains("user"))
			message.fail(FailureCode.NO_USER_KEY_SPECIFIED.getCode(), "No user manager key specified in the msg header.");
		
		
		UserManagerAction action = UserManagerAction.valueOf(message.headers().get("user"));
		
		switch(action){
			
			case SIGN_UP:
				
				this.signUp(message);
				break;
				
			case LOG_IN_REMEMBER_ME:

				this.loginWithRememberMe(message);
				break;
				
			case FIND_USER:

				this.findUser(message);
				break;
				
			default:
				
				message.fail(FailureCode.BAD_USER_ACTION.getCode(), "Bad user action: " + action);
				
		}
	}
	
	
	/**
	 * 
	 *  User action to sign up
	 */
	
	private void signUp(Message<JsonObject> message){
		
		
		JsonObject findUserRequest = new JsonObject().put("username", message.body().getString("signup_email"));
		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERNAME.toString());
		
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findUserRequest,options,reply->{
			
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
				message.fail(((ReplyException)reply.cause()).failureCode(), reply.cause().getMessage());
		});
	}
	
	
	/**
	 * 
	 *  User action to find user
	 */
	
	private void loginWithRememberMe(Message<JsonObject> message){
		
		String username = message.body().getString("username");
		String clearToken = message.body().getString("auth_token");
		
		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_CREATE.toString());
		JsonObject createTokenRequest = new JsonObject();
		createTokenRequest.put("username", username).put("auth_token", clearToken);
		
		LOGGER.debug("[LOG_IN_REMEMBER_ME]Creating token with tokenRequest: " + createTokenRequest);
		
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createTokenRequest, options, reply -> {
					
			if(reply.succeeded()){
				
				String returnedTokenId = reply.result().body().toString();
				LOGGER.debug("[LOG_IN_REMEMBER_ME]Token has been created and stored. Retrieving user.");
				DeliveryOptions opt = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERNAME.toString());
				JsonObject userSelectReq = new JsonObject().put("username", username);
				
				vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), userSelectReq,opt,query->{
					
					if(query.succeeded()){
						JsonObject user = (JsonObject)query.result().body();
						String uId = user.getString("USER_ID");
						LOGGER.debug("[LOG_IN_REMEMBER_ME]User has been retrieved : " + uId);
						message.reply(new JsonObject().put("user", user).put("token_id", returnedTokenId));
					}
					
					else
						message.fail(((ReplyException)reply.cause()).failureCode(), reply.cause().getMessage());
					
				});
			}
			else{
				LOGGER.warn("[LOG_IN_REMEMBER_ME]Token creation failed in DB." + reply.cause());
				message.fail(WarningCode.TOKEN_CREATION_FAILED.getCode(), "Token creation failed.");
			}
		});
	}
	
	/**
	 * 
	 *  User action to find user
	 */
	
	private void findUser(Message<JsonObject> message){
		
		String username,userId;
		
		DeliveryOptions options;
		
		JsonObject findUserRequest = new JsonObject();
		
		if(message.body().getString("username")!=null){
			username = message.body().getString("username");
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERNAME.toString());
			findUserRequest.put("username", username);
		}
		
		else if(message.body().getString("user_id")!=null){
			userId = message.body().getString("user_id");
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERID.toString());
			findUserRequest.put("user_id", userId);
		}
		
		else{
			message.fail(FailureCode.ILLEGAL_ARGUMENT.getCode(), "Illegal argument.");
			return;
		}
		
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findUserRequest,options,reply->{
			
			if(reply.succeeded()){
				
				JsonObject user = (JsonObject)reply.result().body();
				boolean userFound = !user.isEmpty();
				LOGGER.info("[FIND_USER]User found? " + userFound);
				
				if(userFound)
					message.reply(user);
				else
					message.reply(new JsonObject());
				
			}
			
			else{
				LOGGER.error("[FIND_USER]Finding user failed : " + reply.cause());
				message.fail(((ReplyException)reply.cause()).failureCode(), reply.cause().getMessage());
			}
		});
	}

}
