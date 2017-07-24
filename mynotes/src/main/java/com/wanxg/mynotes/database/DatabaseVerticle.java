package com.wanxg.mynotes.database;

import static com.wanxg.mynotes.database.DataBaseQueries.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.mutable.MutableInt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.util.EventBusAddress;
import com.wanxg.mynotes.util.FailureCode;
import com.wanxg.mynotes.util.WarningCode;

import co.paralleluniverse.fibers.Suspendable;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;
import io.vertx.ext.sql.UpdateResult;
import io.vertx.ext.sync.Sync;

public class DatabaseVerticle extends AbstractVerticle {

	private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseVerticle.class);

	public static JDBCClient dbClient;
	public static JDBCAuth authProvider;

	
	@Override
	@Suspendable
	public void start(Future<Void> startFuture) throws Exception {

		LOGGER.info("Starting DatabaseVerticle ...");

		dbClient = JDBCClient.createShared(vertx, new JsonObject().put("url", "jdbc:hsqldb:hsql://localhost/xdb")
				.put("driver_class", "org.hsqldb.jdbcDriver").put("max_pool_size", 30));

		dbClient.getConnection(ar -> {
			if (ar.failed()) {
				LOGGER.error("Could not open a database connection", ar.cause());
				startFuture.fail(ar.cause());
			} else {

				SQLConnection connection = ar.result();
				List<String> sqlStatements = Arrays.asList(SQL_CREATE_TABLE_LOCAL_USER, 
						SQL_CREATE_TABLE_USER_PROFILE, SQL_ALTER_TABLE_USER_PROFILE_ADD_CONSTRAINT_FOREIGN_KEY_UID,
						SQL_CREATE_TABLE_AUTH_TOKEN, SQL_ALTER_TABLE_AUTH_TOKEN_ADD_CONSTRAINT_FOREIGN_KEY_EMAIL, 
						SQL_CREATE_TABLE_USER_ROLE, SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_EMAIL, 
						SQL_CREATE_TABLE_ROLE_PERM, SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_ROLE);

				connection.batch(sqlStatements, res -> {
					connection.close();
					if (res.failed()) {
						LOGGER.error("Database preparation error", res.cause());
						startFuture.fail(res.cause());
					} else {
						LOGGER.info("Listening to " + EventBusAddress.DB_QUEUE_ADDRESS + " on event bus ...");
						vertx.eventBus().consumer(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), Sync.fiberHandler(this::handleOperation));
						LOGGER.info("Database connection established");
						startFuture.complete();
					}
				});
			}
		});

		authProvider = JDBCAuth.create(vertx, dbClient);

	}

	/**
	 * 
	 * method to distribute different DB operations
	 * 
	 * @param message
	 */
	private void handleOperation(Message<JsonObject> message) {

		if (!message.headers().contains("db")) {
			message.fail(FailureCode.NO_DB_KEY_SPECIFIED.getCode(), "No db key specified in the msg header.");
			return;
		}

		DatabaseOperation actionCode = DatabaseOperation.valueOf(message.headers().get("db"));

		switch (actionCode) {

		case USER_CREATE:

			this.createUser(message);
			break;
			
		case USER_UPDATE_ACTIVE:
			
			this.updateUserActiveness(message);
			break;

		case USER_SELECT_BY_EMAIL:

			this.findUserByEmail(message);
			break;

		case USER_SELECT_BY_UID:

			this.findUserById(message);
			break;

			
		case USER_PROFILE_CREATE:
			
			this.createUserProfile(message);
			break;
			
		case USER_PROFILE_SELECT_BY_USER_ID:
			
			this.findUserProfileByUserId(message);
			break;
			
		case AUTH_TOKEN_CREATE:

			this.createAuthToken(message);
			break;

		case AUTH_TOKEN_DELETE:

			this.deleteAuthToken(message);
			break;

		default:
			message.fail(FailureCode.BAD_DB_OPERATION.getCode(), "Bad database operation: " + actionCode);
		}

	}


	/**
	 * DB operation to create a new user, reply the user id
	 * 
	 * @param message
	 */
	@Suspendable
	private void createUser(Message<JsonObject> message) {

		String email = message.body().getString("email");
		String salt = authProvider.generateSalt();
		String hash = authProvider.computeHash(message.body().getString("password"), salt);
		
		
		try (SQLConnection conn = Sync.awaitResult(dbClient::getConnection)) {
			 
			String uid = authProvider.computeHash(email, salt);
			UpdateResult create = Sync.awaitResult(h-> conn.updateWithParams(
					SQL_INSERT_INTO_USER, new JsonArray()
					.add(uid)
					.add(email)
					.add(hash)
					.add(salt), h));
			
			if (create.getUpdated() != 0) {
				LOGGER.info("[USER_CREATE]New user " + email + " has been created.");
				message.reply(uid);
			} else {
				LOGGER.info("[USER_CREATE]User creation failed.");
				message.fail(FailureCode.DB_ERROR.getCode(), "User creation failed.");
			}
		} catch(Exception e){
			LOGGER.error(printStackTrace(e));
			LOGGER.error("[USER_CREATE]User creation failed:" + e.getMessage());
			message.fail(FailureCode.DB_ERROR.getCode(), e.getMessage());
		}
	}
	
	
	/**
	 *  DB operation to make a user inactive, reply an information message
	 *  @param message
	 */
	@Suspendable
	private void updateUserActiveness(Message<JsonObject> message) {
		
		String email = message.body().getString("email");
		Integer activeness = message.body().getInteger("activeness");
		
		try (SQLConnection conn = Sync.awaitResult(dbClient::getConnection)) {
			 
			UpdateResult update = Sync.awaitResult(h-> conn.updateWithParams(SQL_UPDATE_USER_SET_ACTIVE, new JsonArray().add(activeness).add(email), h));
			
			if (update.getUpdated() != 0) {
				LOGGER.info("[USER_UPDATE_ACTIVE]User : " + email + "'s activeness has been updated to " + activeness);
				message.reply("User: " + email + " 's activeness has been updated to " + activeness);
			} else {
				LOGGER.info("[USER_UPDATE_ACTIVE]No record has been updated.");
				message.fail(WarningCode.USER_NOT_FOUND.getCode(), "User not found.");
			}
		} catch(Exception e){
			LOGGER.error(printStackTrace(e));
			LOGGER.error("[USER_UPDATE_ACTIVE]Updating user activeness:" + email + " failed:" + e.getMessage());
			message.fail(FailureCode.DB_ERROR.getCode(), e.getMessage());
		}
		
	}

	/**
	 * DB operation to find a user by email, reply a user json object which can be empty if the user is not found
	 * 
	 * @param message
	 */
	@Suspendable
	private void findUserByEmail(Message<JsonObject> message) {

		String email = message.body().getString("email");

		try (SQLConnection conn = Sync.awaitResult(dbClient::getConnection)) {
			 
			ResultSet query = Sync.awaitResult(h-> conn.queryWithParams(SQL_SELECT_USER_BY_EMAIL, new JsonArray().add(email), h));
			
			LOGGER.debug("[USER_SELECT_BY_EMAIL]Query successful");
			LOGGER.info("[USER_SELECT_BY_EMAIL]User found: " + query.getNumRows());
			if (query.getNumRows() != 0) {
					
				LOGGER.debug(query.getRows().toString());
				message.reply(query.getRows().get(0));
			}
			else{
				
				LOGGER.info("[USER_SELECT_BY_EMAIL]User not found.");
				message.reply(new JsonObject());
			}
		} catch(Exception e){
			LOGGER.error(printStackTrace(e));
			LOGGER.error("[USER_SELECT_BY_EMAIL]Querying user for email " + email + " failed: " + e.getMessage());
			message.fail(FailureCode.DB_ERROR.getCode(), e.getMessage());
		}
		 
		
	}

	/**
	 * DB operation to find a user by user id, reply a user json object which can be empty if the user is not found
	 * 
	 * @param message
	 */
	@Suspendable
	private void findUserById(Message<JsonObject> message) {

		String uid = message.body().getString("uid");

		try (SQLConnection conn = Sync.awaitResult(dbClient::getConnection)) {
			 
			ResultSet query = Sync.awaitResult(h-> conn.queryWithParams(SQL_SELECT_USER_BY_UID, new JsonArray().add(uid), h));
			
			LOGGER.debug("[USER_SELECT_BY_UID]Query successful");
			LOGGER.info("[USER_SELECT_BY_UID]User found: " + query.getNumRows());
			if (query.getNumRows() != 0) {
					
				LOGGER.debug(query.getRows().toString());
				message.reply(query.getRows().get(0));
			}
			else{
				LOGGER.info("[USER_SELECT_BY_UID]User not found.");
				message.reply(new JsonObject());
			}
		} catch(Exception e){
			LOGGER.error(printStackTrace(e));
			LOGGER.error("[USER_SELECT_BY_USERID]Querying user for user id " + uid + " failed:" + e.getMessage());
			message.fail(FailureCode.DB_ERROR.getCode(), e.getMessage());
		}
		
	}
	
	
	/**
	 * DB operation to create a new user profile, reply the profile id
	 * 
	 * @param message
	 */
	@Suspendable
	private void createUserProfile(Message<JsonObject> message) {
		
		String uid = message.body().getString("uid");
		String email = message.body().getString("email");
		String username = message.body().getString("username");
		String firstName = message.body().getString("firstName");
		String lastName = message.body().getString("lastName");
		String photoUrl = message.body().getString("photoUrl");
		Integer gender = message.body().getInteger("gender");
		
		try (SQLConnection conn = Sync.awaitResult(dbClient::getConnection)) {
			
			JsonArray params = new JsonArray();
			
			if(uid==null) params.addNull(); else params.add(uid);
			params.add(email);
			params.add(username);
			if(firstName==null) params.addNull(); else params.add(firstName);
			if(lastName==null) params.addNull(); else params.add(lastName);
			if(photoUrl==null) params.addNull(); else params.add(photoUrl);
			if(gender==null) params.addNull(); else params.add(gender);
			
			UpdateResult create = Sync.awaitResult(h-> conn.updateWithParams(
					
					SQL_INSERT_INTO_USER_PROFILE, params,h));
			
			if (create.getUpdated() != 0) {
				
				LOGGER.info("[USER_PROFILE_CREATE]New user profile has been created for: " + email);
				message.reply(create.getKeys().getInteger(0));
				
			} else {
				LOGGER.info("[USER_PROFILE_CREATE]User profile creation failed.");
				message.fail(FailureCode.DB_ERROR.getCode(), "User profile creation failed.");
			}
			
		} catch(Exception e){
			LOGGER.error(printStackTrace(e));
			LOGGER.error("[USER_PROFILE_CREATE]User profile creation failed:" + e.getCause());
			message.fail(FailureCode.DB_ERROR.getCode(), e.getMessage());
		}
		
	}
	
	
	/**
	 * DB operation to find a user profile by user id, reply a user profile json object which can be empty if the user is not found
	 * 
	 * @param message
	 */
	@Suspendable
	private void findUserProfileByUserId(Message<JsonObject> message) {
		
		String userId = message.body().getString("userId");
		
		try (SQLConnection conn = Sync.awaitResult(dbClient::getConnection)) {
			 
			ResultSet query = Sync.awaitResult(h-> conn.queryWithParams(SQL_SELECT_USER_PROFILE_BY_USER_ID, new JsonArray().add(userId), h));
			
			LOGGER.debug("[USER_PROFILE_SELECT_BY_USER_ID]Query successful");
			LOGGER.info("[USER_PROFILE_SELECT_BY_USER_ID]User profile found: " + query.getNumRows());
			if (query.getNumRows() != 0) {
					
				LOGGER.debug(query.getRows().toString());
				message.reply(query.getRows().get(0));
			}
			else{
				LOGGER.info("[USER_PROFILE_SELECT_BY_USER_ID]User profile not found.");
				message.reply(new JsonObject());
			}
		} catch(Exception e){
			LOGGER.error(printStackTrace(e));
			LOGGER.error("[USER_PROFILE_SELECT_BY_USER_ID]Querying user profile for user id " + userId + " failed:" + e.getMessage());
			message.fail(FailureCode.DB_ERROR.getCode(), e.getMessage());
		}
		
	}
	

	/**
	 * DB operation to create a new authentication token for login with cookie, reply the id of the created token
	 * 
	 * @param message
	 */
	@Suspendable
	private void createAuthToken(Message<JsonObject> message) {
		String email = message.body().getString("email");
		String token = message.body().getString("auth_token");
		Long validTo = message.body().getLong("valid_to");

		String salt = authProvider.generateSalt();
		String hash = authProvider.computeHash(token, salt);

		MutableInt maxTokenId = new MutableInt(DataBaseQueries.TOKEN_INITIAL_ID);

		try (SQLConnection conn = Sync.awaitResult(dbClient::getConnection)) {
			
			
			ResultSet query = Sync.awaitResult(h-> conn.query(SQL_SELECT_MAX_TOKEN_ID, h));
			
			if (!query.getResults().get(0).hasNull(0))
				maxTokenId.setValue(Integer.valueOf(query.getResults().get(0).getString(0)));

			LOGGER.debug("[USER_TOKEN_CREATE]Max token id is :" + maxTokenId.getValue());
			
			UpdateResult create = Sync.awaitResult(h-> conn.updateWithParams(
												SQL_INSERT_INTO_AUTH_TOKEN, new JsonArray()
																					.add(String.valueOf(maxTokenId.getValue() + 1))
																					.add(email)
																					.add(hash)
																					.add(salt)
																					.add(new java.sql.Timestamp(validTo).toString()),h));
			if (create.getUpdated() != 0) {
				LOGGER.info("[USER_TOKEN_CREATE]" + create.getUpdated()
						+ " new token has been created for the user: " + email + " with id: "
						+ (maxTokenId.getValue() + 1));
				message.reply(maxTokenId.getValue() + 1);
			} else {
				LOGGER.info("[USER_TOKEN_CREATE]No token has been created");
				message.fail(FailureCode.DB_ERROR.getCode(), "No token has been created");
			}
			
		} catch(Exception e){
			LOGGER.error(printStackTrace(e));
			LOGGER.error("[USER_TOKEN_CREATE]Creating a new token for the user: " + email + " failed:" + e.getMessage());
			message.fail(FailureCode.DB_ERROR.getCode(), e.getMessage());
		}
		
	}

	/**
	 * DB operation to delete a token, reply an information message
	 * 
	 * @param message
	 */
	@Suspendable
	private void deleteAuthToken(Message<JsonObject> message) {

		String tokenId = message.body().getString("token_id");
		
		try (SQLConnection conn = Sync.awaitResult(dbClient::getConnection)) {
			 
			UpdateResult delete = Sync.awaitResult(h-> conn.updateWithParams(SQL_UPDATE_AUTH_TOKEN_SET_INVALID, new JsonArray().add(tokenId), h));
			
			if (delete.getUpdated() != 0) {
				LOGGER.info("[AUTH_TOKEN_DELETE]Token with id : " + tokenId + " has been deleted.");
				message.reply("Token with id :" + tokenId + " has been deleted.");
			} else {
				LOGGER.info("[AUTH_TOKEN_DELETE]No token has been deleted.");
				message.fail(WarningCode.TOKEN_NOT_FOUND.getCode(), "Token for deletion not found.");
			}
		
		} catch(Exception e){
			LOGGER.error(printStackTrace(e));
			LOGGER.error("[AUTH_TOKEN_DELETE]Deleting token: " + tokenId + " failed:" + e.getMessage());
			message.fail(FailureCode.DB_ERROR.getCode(), e.getMessage());
		}

	}
	
	private String printStackTrace(Exception e){
		StringWriter sw = new StringWriter();
		e.printStackTrace(new PrintWriter(sw));
		return sw.toString();
	}

}