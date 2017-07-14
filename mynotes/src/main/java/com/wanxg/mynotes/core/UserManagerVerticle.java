package com.wanxg.mynotes.core;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.database.DatabaseOperation;
import com.wanxg.mynotes.util.EventBusAddress;
import com.wanxg.mynotes.util.FailureCode;

import co.paralleluniverse.fibers.Suspendable;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.eventbus.ReplyException;
import io.vertx.core.json.JsonObject;

import io.vertx.ext.sync.Sync;

public class UserManagerVerticle extends AbstractVerticle {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(UserManagerVerticle.class);
	
	@Override
	@Suspendable
	public void start(Future<Void> startFuture) throws Exception {
		
		LOGGER.info("Starting UserManagerVerticle ...");
		
		LOGGER.info("Listening to " + EventBusAddress.USER_MANAGER_QUEUE_ADDRESS + " on event bus ...");
		vertx.eventBus().consumer(EventBusAddress.USER_MANAGER_QUEUE_ADDRESS.getAddress(), Sync.fiberHandler(this::distributeAction));
		startFuture.complete();
	}
	
	/**
	 * A user action distributor distributing user actions based on the UserManagerAction provided in the header.
	 * 
	 * @param message
	 */
	private void distributeAction(Message<JsonObject> message){
		
		if(!message.headers().contains("user"))
			message.fail(FailureCode.NO_USER_KEY_SPECIFIED.getCode(), "No user manager key specified in the msg header.");
		
		
		UserManagerAction action = UserManagerAction.valueOf(message.headers().get("user"));
		
		switch(action){
			
			case SIGN_UP:
				
				this.signUp(message);
				break;
				
			case REMEMBER_ME:

				this.rememberMe(message);
				break;
				
			case FIND_USER:

				this.findUser(message);
				break;
				
			case MANAGE_TOKEN:
				
				this.manageToken(message);
				break;
			
			default:
				
				message.fail(FailureCode.BAD_USER_ACTION.getCode(), "Bad user action: " + action);
				
		}
	}
	
	
	/**
	 * 
	 * User action to sign up
	 * @param message
	 */
	@Suspendable
	private void signUp(Message<JsonObject> message){
		
		String email = message.body().getString("signup_email");
		String fullname = message.body().getString("full_name");
		String password = message.body().getString("signup_password");
		
		if(email==null || fullname==null || password==null){
			message.fail(FailureCode.ILLEGAL_ARGUMENT.getCode(), "Illegal argument.");
			return;
		}
		
		JsonObject findUserRequest = new JsonObject().put("username", email);
		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERNAME.toString());

		try{
			
			Message<JsonObject> reply = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findUserRequest,options,h));
			JsonObject body = (JsonObject)reply.body();
			boolean userExists = !body.isEmpty();
			LOGGER.debug("user exists? " + userExists);
			if(!userExists){
				
				DeliveryOptions opt = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_CREATE.toString());
				JsonObject createUserRequest = new JsonObject()
						.put("username", email)
						.put("fullname", fullname)
						.put("password", password);
				
				reply = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createUserRequest,opt,h));
				message.reply(reply.body().toString());
				
			}
			else{
				LOGGER.error("[SIGN_UP]The Provided email is already registered.");
				message.fail(FailureCode.EMAIL_ALREADY_EXISTS.getCode(), "The Provided email is already registered.");
			}
			
		}
		
		catch(Exception e){
			
			ReplyException re = (ReplyException)e.getCause();
			LOGGER.error("[SIGN_UP]Sign up failed: " + e.getMessage());
			message.fail(re.failureCode(), e.getMessage());
			
		}
		
	}
	
	
	/**
	 * User action to log in with remember me option checked
	 * 
	 * @param message
	 */
	@Suspendable
	private void rememberMe(Message<JsonObject> message){
		
		String username = message.body().getString("username");
		String clearToken = message.body().getString("auth_token");
		Long validTo = message.body().getLong("valid_to");
		
		if(username==null || clearToken==null || validTo==null){
			message.fail(FailureCode.ILLEGAL_ARGUMENT.getCode(), "Illegal argument.");
			return;
		}
		
		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_CREATE.toString());
		JsonObject createTokenRequest = new JsonObject();
		createTokenRequest.put("username", username).put("auth_token", clearToken).put("valid_to", validTo);
		
		LOGGER.debug("[REMEMBER_ME]Creating token with tokenRequest: " + createTokenRequest);
		
		try{
			
			Message<Integer> reply = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createTokenRequest,options,h));
			String returnedTokenId = reply.body().toString();
			
			LOGGER.debug("[REMEMBER_ME]Token has been created and stored. Retrieving user.");
			
			DeliveryOptions opt = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERNAME.toString());
			JsonObject userSelectReq = new JsonObject().put("username", username);
			
			Message<JsonObject> query = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), userSelectReq,opt,h));
			JsonObject user = (JsonObject)query.body();
			String uId = user.getString("USER_ID");
			
			LOGGER.debug("[REMEMBER_ME]User has been retrieved : " + uId);
			
			message.reply(new JsonObject().put("user", user).put("token_id", returnedTokenId));
		
		}
		
		catch(Exception e){
			
			ReplyException re = (ReplyException)e.getCause();
			LOGGER.warn("[REMEMBER_ME]Token creation failed: " + e.getMessage());
			message.fail(re.failureCode(), e.getMessage());
			
		}
		
	}
	
	/**
	 * User action to find user
	 * @param message
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
	
	/**
	 *  User action to manage token, the sub-action defining the operation is provided in the header.
	 * 
	 * @param message
	 */
	@Suspendable
	private void manageToken(Message<JsonObject> message){
		
		UserManagerAction subAction = UserManagerAction.valueOf(message.headers().get("sub_action"));
		String tokenId = message.body().getString("token_id");
		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_DELETE.toString());
		JsonObject deleteTokenRequest = new JsonObject().put("token_id", tokenId);
		
		switch (subAction) {
		
			case DELETE_TOKEN:
				
				
				vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), deleteTokenRequest, options, reply -> {
					
					if (reply.succeeded()) {
						LOGGER.info("[MANAGE_TOKEN]" + reply.result().body().toString());
					}
					else {
						LOGGER.info("[MANAGE_TOKEN]Deleting token failed : " + reply.cause());
					}
				});
				
				break;
				
			case REISSUE_TOKEN:
				
				
				String userHash = message.body().getString("user_id");
				String clearToken = message.body().getString("auth_token");
				Long validTo = message.body().getLong("valid_to");
				
				// Delete old token
				Message<String> delete = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), deleteTokenRequest,options,h));
				LOGGER.info("[MANAGE_TOKEN]" + delete.body());
				
				// Search for user with user hash
				DeliveryOptions findOpt = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_USERID.toString());
				Message<JsonObject> find = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), new JsonObject().put("user_id", userHash),findOpt,h));
				
				JsonObject user = find.body();
				LOGGER.debug("[MANAGE_TOKEN]Returned user: " + user);
				String username = find.body().getString("USERNAME");
				
				// Create a new token, return the new token id
				DeliveryOptions createOpt = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_CREATE.toString());
				JsonObject createTokenRequest = new JsonObject().put("username", username).put("auth_token", clearToken).put("valid_to", validTo);
				Message<Integer> newTokenId = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createTokenRequest,createOpt,h));
				LOGGER.info("[MANAGE_TOKEN]A new token has been issue with id: " + newTokenId.body());
				
				message.reply(new JsonObject().put("user", user).put("token_id", newTokenId.body()));
				
				break;
			
			
			default:
				message.fail(FailureCode.BAD_USER_SUB_ACTION.getCode(), "Bad user sub action: " + subAction);
				
			
		}
		
		
		
		
	}

}
