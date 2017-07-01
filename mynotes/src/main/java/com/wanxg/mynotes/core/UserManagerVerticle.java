package com.wanxg.mynotes.core;

import com.wanxg.mynotes.EventBusAddress;
import com.wanxg.mynotes.database.DatabaseOperation;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

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
			message.fail(UserManagerErrorCode.NO_USER_KEY_SPECIFIED.getCode(), "No user manager key specified in the msg header.");
		
		
		UserManagerAction action = UserManagerAction.valueOf(message.headers().get("user"));
		
		switch(action){
			
			case SIGN_UP:
				
				DeliveryOptions options = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_FIND.toString());
				JsonObject userExistsRequest = new JsonObject().put("email", message.body().getString("signup_email"));
				
				vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), userExistsRequest,options,reply->{
					
					if(reply.succeeded()){
						
						JsonObject body = (JsonObject) reply.result().body();
						boolean userExists = body.getBoolean("userExists");
						if(!userExists){
							
							
							DeliveryOptions opt = new DeliveryOptions().addHeader("db", DatabaseOperation.USER_CREATE.toString());
							JsonObject createUserRequest = new JsonObject()
									.put("email", message.body().getString("signup_email"))
									.put("username", message.body().getString("fullName"))
									.put("password", message.body().getString("signup_password"));
							
							
							vertx.eventBus().send(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), createUserRequest,opt);
							message.reply("User has been registered");
						}
						
						else
							LOGGER.error("[SIGN_UP]eMail already exists");
							message.fail(UserManagerErrorCode.EMAIL_ALREADY_EXISTS.getCode(), "Provided email already registered.");
					}
					
					else
						message.fail(UserManagerErrorCode.EVENTBUS_ERROR.getCode(), reply.cause().getMessage());
				});

				
				
				break;
				
			default:
				
				message.fail(UserManagerErrorCode.BAD_USER_ACTION.getCode(), "Bad user action: " + action);
				
		}
	}

}
