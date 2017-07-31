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
				
			case SOCIAL_SIGN_UP:
				
				this.socialSignUp(message);
				break;	
				
			case REMEMBER_ME:

				this.rememberMe(message);
				break;
				
			case FIND_USER:

				this.findUser(message);
				break;
				
			case FIND_USER_PROFILE:

				this.findUserProfile(message);
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
	 * User action to sign up, reply a new user profile
	 * @param message
	 */
	@Suspendable
	private void signUp(Message<JsonObject> message){
		
		String email = message.body().getString("signup_email");
		String username = message.body().getString("user_name");
		String password = message.body().getString("signup_password");
		
		if(email==null || username==null || password==null){
			message.fail(FailureCode.ILLEGAL_ARGUMENT.getCode(), "Illegal argument.");
			return;
		}
		
		JsonObject findUserRequest = new JsonObject().put("email", email);
		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_EMAIL.toString());

		try{
			
			Message<JsonObject> query = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findUserRequest,options,h));
			JsonObject user = (JsonObject)query.body();
			boolean userExists = !user.isEmpty();
			LOGGER.debug("[SIGN_UP]User exists? " + userExists);
			if(!userExists){
				
				DeliveryOptions optUser = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_CREATE.toString());
				JsonObject createUserRequest = new JsonObject()
						.put("email", email)
						.put("password", password);
				
				Message<String> userResult = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createUserRequest,optUser,h));
				
				String userId = userResult.body();
				
				LOGGER.debug("[SIGN_UP]User has been created with id: " + userId);
				
				DeliveryOptions optProfile = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_PROFILE_CREATE.toString());
				JsonObject createUserProfileRequest = new JsonObject()
						.put("userId", userId)
						.put("email", email)
						.put("username",username);
				
				Message<JsonObject> profileResult = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createUserProfileRequest,optProfile,h));
				
				JsonObject userProfile = profileResult.body();
				
				LOGGER.debug("[SIGN_UP]User profile has been created: " + userProfile);
				
				message.reply(userProfile);
				
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
	 * 
	 *  User action to sign up with external social login
	 */
	@Suspendable
	private void socialSignUp(Message<JsonObject> message){
		
		String email = message.body().getString("email");
		String username = message.body().getString("username");
		String firstName = message.body().getString("firstName");
		String lastName = message.body().getString("lastName");
		String photoUrl = message.body().getString("photoUrl");
		Integer gender =  "male".equals(message.body().getString("gender"))? 1:0;
		String externalId = message.body().getString("externalId");
		
		try{
			
			// use the external id to find if the social user has been already signed up before.
			DeliveryOptions findSocialUserOptions = new DeliveryOptions().addHeader("db", DatabaseOperation.SOCIAL_USER_SELECT_BY_EXTERNAL_ID.toString());
			JsonObject findSocialUserRequest = new JsonObject().put("externalId", externalId);
			Message<JsonObject> queryResult = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findSocialUserRequest,findSocialUserOptions,h));
			
			JsonObject socialUser = queryResult.body();
			
			if(!socialUser.isEmpty()){
				
				LOGGER.info("[SOCIAL_SIGN_UP]Social user has been already signed up with : " + socialUser);
				
				// use the latest user info to update social user stored in the db. 
				// TODO: update user profile?
				DeliveryOptions updateOptions = new DeliveryOptions().addHeader("db", DatabaseOperation.SOCIAL_USER_UPDATE.toString());
				JsonObject updateSocialUserRequest = new JsonObject()
						.put("externalId", externalId)
						.put("email", email)
						.put("username",username)
						.put("firstName",firstName)
						.put("lastName",lastName)
						.put("photoUrl",photoUrl)
						.put("gender",gender);
				Message<String> updateResult = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), updateSocialUserRequest,updateOptions,h));
				
				LOGGER.info("[SOCIAL_SIGN_UP]" + updateResult.body());
				
				// find the user profile
				Integer profileId = socialUser.getInteger("PROFILE_ID");
				DeliveryOptions findProfileOptions = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_PROFILE_SELECT_BY_PROFILE_ID.toString());
				JsonObject findProfileRequest = new JsonObject().put("pid", profileId);
				Message<JsonObject> result = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findProfileRequest,findProfileOptions,h));
				JsonObject userProfile = result.body();
				message.reply(userProfile);
				
			}
			
			else {
				
				// create a new user profile
				DeliveryOptions profileOptions = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_PROFILE_CREATE.toString());
				JsonObject createUserProfileRequest = new JsonObject()
						.put("email", email)
						.put("username",username)
						.put("firstName",firstName)
						.put("lastName",lastName)
						.put("photoUrl",photoUrl)
						.put("gender",gender);
				
				Message<JsonObject> profileResult = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createUserProfileRequest,profileOptions,h));
				
				JsonObject userProfile = profileResult.body();
				
				LOGGER.info("[SOCIAL_SIGN_UP]User profile has been created: " + userProfile);
				
				Integer profileId = userProfile.getInteger("PID");
				String socialProvider = message.body().getString("socialProvider");
				
				
				// create a new social user record
				DeliveryOptions socialOptions = new DeliveryOptions().addHeader("db", DatabaseOperation.SOCIAL_USER_CREATE.toString());
				
				JsonObject createSocialUserRequest = new JsonObject()
						.put("profileId", profileId)
						.put("socialProvider",socialProvider)
						.put("externalId", externalId)
						.put("email", email)
						.put("username",username)
						.put("firstName",firstName)
						.put("lastName",lastName)
						.put("photoUrl",photoUrl)
						.put("gender",gender);
				
				Message<Integer> socialResult = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createSocialUserRequest,socialOptions,h));
				
				LOGGER.info("[SOCIAL_SIGN_UP]Social user has been created: " + socialResult.body());
				message.reply(userProfile);
			}
		
		} catch(Exception e){
			
			ReplyException re = (ReplyException)e.getCause();
			LOGGER.warn("[SOCIAL_SIGN_UP]Social signing up failed: " + e.getMessage());
			message.fail(re.failureCode(), e.getMessage());
			
		}
		
	}
	
	
	
	/**
	 * User action to log in with remember me option checked, reply a new token id
	 * 
	 * @param message
	 */
	@Suspendable
	private void rememberMe(Message<JsonObject> message){
		
		String userId = message.body().getString("userId");
		String clearToken = message.body().getString("auth_token");
		Long validTo = message.body().getLong("valid_to");
		
		if(userId==null || clearToken==null || validTo==null){
			message.fail(FailureCode.ILLEGAL_ARGUMENT.getCode(), "Illegal argument.");
			return;
		}
		
		
		
		
		DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_CREATE.toString());
		JsonObject createTokenRequest = new JsonObject();
		createTokenRequest.put("userId", userId).put("auth_token", clearToken).put("valid_to", validTo);
		
		LOGGER.debug("[REMEMBER_ME]Creating token with tokenRequest: " + createTokenRequest);
		
		try{
			
			Message<Integer> reply = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createTokenRequest,options,h));
			String returnedTokenId = reply.body().toString();
			message.reply(returnedTokenId);
		
		}
		
		catch(Exception e){
			
			ReplyException re = (ReplyException)e.getCause();
			LOGGER.warn("[REMEMBER_ME]Token creation failed: " + e.getMessage());
			message.fail(re.failureCode(), e.getMessage());
			
		}
		
	}
	
	/**
	 * User action to find user, reply the found user json object or an empty one
	 * @param message
	 */
	
	@Deprecated
	private void findUser(Message<JsonObject> message){
		
		String email,userId;
		
		DeliveryOptions options;
		
		JsonObject findUserRequest = new JsonObject();
		
		if(message.body().getString("email")!=null){
			email = message.body().getString("email");
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_EMAIL.toString());
			findUserRequest.put("email", email);
		}
		
		else if(message.body().getString("uid")!=null){
			userId = message.body().getString("uid");
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_SELECT_BY_UID.toString());
			findUserRequest.put("uid", userId);
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
	 * 
	 *  User action to find user profile with provided argument, reply a found user profile json object or an empty one
	 * 
	 */
	
	private void findUserProfile(Message<JsonObject> message){
		
		String email,userId;
		Integer pid;
		
		DeliveryOptions options;
		
		JsonObject findUserProfileRequest = new JsonObject();
		
		if(message.body().getString("email")!=null){
			email = message.body().getString("email");
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_PROFILE_SELECT_BY_EMAIL.toString());
			findUserProfileRequest.put("email", email);
		}
		
		else if(message.body().getInteger("pid")!=null){
			pid = message.body().getInteger("pid");
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_PROFILE_SELECT_BY_PROFILE_ID.toString());
			findUserProfileRequest = new JsonObject().put("pid", pid);
		}
		
		else if(message.body().getString("userId")!=null){
			userId = message.body().getString("userId");
			options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_PROFILE_SELECT_BY_USER_ID.toString());
			findUserProfileRequest = new JsonObject().put("userId", userId);
		}
		
		else{
			message.fail(FailureCode.ILLEGAL_ARGUMENT.getCode(), "Illegal argument.");
			return;
		}
		
		vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), findUserProfileRequest,options,reply->{
			
			if(reply.succeeded()){
				
				JsonObject userProfile = (JsonObject)reply.result().body();
				boolean found = !userProfile.isEmpty();
				LOGGER.info("[FIND_USER_PROFILE]User profile found? " + found);
				
				if(found)
					message.reply(userProfile);
				else
					message.reply(new JsonObject());
				
			}
			
			else{
				LOGGER.error("[FIND_USER_PROFILE]Finding user profile failed : " + reply.cause());
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
						LOGGER.info("[DELETE_TOKEN]" + reply.result().body().toString());
					}
					else {
						LOGGER.info("[DELETE_TOKEN]Deleting token failed : " + reply.cause());
					}
				});
				
				break;
				
			case REISSUE_TOKEN:
				
				
				String userId = message.body().getString("userId");
				String clearToken = message.body().getString("auth_token");
				Long validTo = message.body().getLong("valid_to");
				
				try{
				
					// Delete old token
					Message<String> delete = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), deleteTokenRequest,options,h));
					LOGGER.info("[REISSUE_TOKEN]" + delete.body());
					
					// Create a new token, return the new token id
					DeliveryOptions createOpt = new DeliveryOptions().addHeader("db", DatabaseOperation.AUTH_TOKEN_CREATE.toString());
					JsonObject createTokenRequest = new JsonObject().put("userId", userId).put("auth_token", clearToken).put("valid_to", validTo);
					Message<Integer> newTokenId = Sync.awaitResult(h -> vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createTokenRequest,createOpt,h));
					LOGGER.info("[REISSUE_TOKEN]A new token has been issue with id: " + newTokenId.body());
					
					message.reply(newTokenId.body());
				}
				
				catch(Exception e){
					
					ReplyException re = (ReplyException)e.getCause();
					LOGGER.warn("[REISSUE_TOKEN]Reissue token failed: " + e.getMessage());
					message.fail(re.failureCode(), e.getMessage());
					
				}
				
				break;
			
			
			default:
				
				message.fail(FailureCode.BAD_USER_SUB_ACTION.getCode(), "Bad user sub action: " + subAction);
				
		}
		
	}

}
