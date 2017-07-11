package com.wanxg.mynotes.database;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.mutable.MutableInt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.util.EventBusAddress;
import com.wanxg.mynotes.util.FailureCode;
import com.wanxg.mynotes.util.WarningCode;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

public class DatabaseVerticle extends AbstractVerticle {

	private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseVerticle.class);

	public static JDBCClient dbClient;
	public static JDBCAuth authProvider;

	/*************************************************DDL***************************************************/
	
	private static final String SQL_CREATE_TABLE_USER = "CREATE TABLE IF NOT EXISTS user ("
			+ "user_id VARCHAR(255) NOT NULL, "
			+ "username VARCHAR(255) NOT NULL PRIMARY KEY, "
			+ "fullname VARCHAR(255) NOT NULL, "
			+ "password VARCHAR(255) NOT NULL, "
			+ "password_salt VARCHAR(255) NOT NULL, "
			+ "creation TIMESTAMP(0) DEFAULT NOW,"
			+ "active INTEGER DEFAULT 1 NOT NULL)";

	
	private static final String SQL_CREATE_TABLE_AUTH_TOKEN = "CREATE TABLE IF NOT EXISTS auth_token ("
			+ "id VARCHAR(10) NOT NULL, "
			+ "username VARCHAR(255) NOT NULL, "
			+ "token VARCHAR(255) NOT NULL, "
			+ "token_salt VARCHAR(255) NOT NULL, "
			+ "creation TIMESTAMP(0) DEFAULT NOW NOT NULL, "
			+ "valid_to TIMESTAMP(0) NOT NULL, "
			+ "deleted INTEGER DEFAULT 0 NOT NULL, "
			+ "PRIMARY KEY (username,token))";
	
	private static final String SQL_ALTER_TABLE_AUTH_TOKEN_ADD_CONSTRAINT_FOREIGN_KEY_USERNAME = "ALTER TABLE auth_token ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_auth_token_username FOREIGN KEY (username) REFERENCES user(username)";
	
	
	private static final String SQL_CREATE_TABLE_USER_ROLE = "CREATE TABLE IF NOT EXISTS user_role ("
			+ "username VARCHAR(255) NOT NULL, "
			+ "role VARCHAR(255) NOT NULL, "
			+ "PRIMARY KEY (username,role))";

	private static final String SQL_CREATE_TABLE_ROLE_PERM = "CREATE TABLE IF NOT EXISTS role_perm ("
			+ "role VARCHAR(255) NOT NULL PRIMARY KEY, "
			+ "permission VARCHAR(255) NOT NULL)";

	private static final String SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_USERNAME = "ALTER TABLE user_role ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_user_role_username FOREIGN KEY (username) REFERENCES user(username)";

	private static final String SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_ROLE = "ALTER TABLE user_role ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_user_role_role FOREIGN KEY (role) REFERENCES role_perm(role)";

	
	/***********************************************DML******************************************************/
	
	private static final String SQL_SELECT_USER_BY_USERNAME = "SELECT * FROM user WHERE username = ?";
	
	private static final String SQL_SELECT_USER_BY_USER_ID = "SELECT * FROM user WHERE user_id = ?";
	
	private static final String SQL_INSERT_INTO_USER = "INSERT INTO user (user_id,username,fullname,password,password_salt) VALUES (?,?,?,?,?)";
	
	private static final String SQL_UPDATE_USER_SET_ACTIVE = "UPDATE user SET ACTIVE = ? WHERE username = ?";
	
	private static final String SQL_SELECT_MAX_TOKEN_ID = "SELECT max(id) FROM auth_token";
	
	private static final String SQL_INSERT_INTO_AUTH_TOKEN = "INSERT INTO auth_token (id,username,token,token_salt,valid_to) VALUES (?,?,?,?, TO_TIMESTAMP(?, 'YYYY-MM-DD HH:MI:SS' ))";
	
	private static final String SQL_UPDATE_AUTH_TOKEN_SET_INVALID = "UPDATE auth_token SET deleted = 1 WHERE id = ?";
	
	public static final String SQL_SELECT_AUTH_TOKEN_BY_USER_ID_AND_TOKEN_ID = 
			"SELECT token, token_salt FROM auth_token LEFT JOIN user ON auth_token.username = user.username WHERE user.user_id = ? AND auth_token.id = ?";
	
	public static final String AUTHENTICATE_QUERY_FOR_TOKEN = "SELECT token, token_salt FROM auth_token WHERE id = ? AND deleted = 0 AND valid_to >= NOW()";
	
	@Override
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
				List<String> sqlStatements = Arrays.asList(SQL_CREATE_TABLE_USER, SQL_CREATE_TABLE_AUTH_TOKEN,
						SQL_ALTER_TABLE_AUTH_TOKEN_ADD_CONSTRAINT_FOREIGN_KEY_USERNAME, SQL_CREATE_TABLE_USER_ROLE,
						SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_USERNAME, SQL_CREATE_TABLE_ROLE_PERM,
						SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_ROLE);

				connection.batch(sqlStatements, res -> {
					connection.close();
					if (res.failed()) {
						LOGGER.error("Database preparation error", res.cause());
						startFuture.fail(res.cause());
					} else {
						LOGGER.info("Listening to " + EventBusAddress.DB_QUEUE_ADDRESS + " on event bus ...");
						vertx.eventBus().consumer(EventBusAddress.DB_QUEUE_ADDRESS.getAddress(), this::handleOperation);
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

		case USER_SELECT_BY_USERNAME:

			this.findUserByUsername(message);
			break;

		case USER_SELECT_BY_USERID:

			this.findUserById(message);
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
	 * DB operation to create a new user, reply an information message
	 * 
	 * @param message
	 */
	private void createUser(Message<JsonObject> message) {

		String username = message.body().getString("username");
		String salt = authProvider.generateSalt();
		String hash = authProvider.computeHash(message.body().getString("password"), salt);

		// System.out.println("salt: " + salt);
		// System.out.println("hash: " + hash);

		dbClient.getConnection(ar -> {
			if (ar.failed()) {
				LOGGER.error("[USER_CREATE]Could not open a database connection", ar.cause());
				message.fail(503, "Database unavailable: " + ar.cause());
			} else {
				SQLConnection connection = ar.result();
				connection
						.updateWithParams(
								SQL_INSERT_INTO_USER, new JsonArray()
														.add(authProvider.computeHash(username, salt))
														.add(username)
														.add(message.body().getString("fullname"))
														.add(hash)
														.add(salt),
								res -> {
									connection.close();
									if (res.failed()) {
										LOGGER.error("[USER_CREATE]Creating new user failed: " + res.cause());
										message.fail(FailureCode.DB_ERROR.getCode(), res.cause().getMessage());
									} else {

										if (res.result().getUpdated() != 0) {
											LOGGER.info("[USER_CREATE]New user has been created.");
											message.reply("User: " + username + " has been created");
										} else {
											LOGGER.info("[USER_CREATE]User creation failed.");
											message.fail(FailureCode.DB_ERROR.getCode(), "User creation failed.");
										}
									}
								});
			}
		});
	}
	
	
	/**
	 *  DB operation to make a user inactive, reply an information message
	 *  @param message
	 */
	private void updateUserActiveness(Message<JsonObject> message) {
		
		String username = message.body().getString("username");
		Integer activeness = message.body().getInteger("activeness");
		
		dbClient.getConnection(ar -> {
			if (ar.failed()) {
				LOGGER.error("[USER_UPDATE_ACTIVE]Could not open a database connection", ar.cause());
				message.fail(503, "Database unavailable: " + ar.cause());
			} else {
				SQLConnection connection = ar.result();
				connection.updateWithParams(SQL_UPDATE_USER_SET_ACTIVE, new JsonArray().add(activeness).add(username), delete -> {
					connection.close();
					if (delete.failed()) {
						LOGGER.error("[USER_UPDATE_ACTIVE]Updating user activeness:" + username + " failed.", delete.cause());
						message.fail(FailureCode.DB_ERROR.getCode(), delete.cause().getMessage());

					} else {

						if (delete.result().getUpdated() != 0) {
							LOGGER.info("[USER_UPDATE_ACTIVE]User : " + username + "'s activeness has been updated to " + activeness);
							message.reply("User: " + username + " 's activeness has been updated to " + activeness);
						} else {
							LOGGER.info("[USER_UPDATE_ACTIVE]No record has been updated.");
							message.fail(WarningCode.USER_NOT_FOUND.getCode(), "User not found.");
						}

					}
				});
			}
		});
		
	}

	/**
	 * DB operation to find a user by user name, reply a user json object which can be empty if the user is not found
	 * 
	 * @param message
	 */
	private void findUserByUsername(Message<JsonObject> message) {

		String username = message.body().getString("username");

		dbClient.getConnection(ar -> {
			if (ar.failed()) {
				LOGGER.error("[USER_SELECT_BY_USERNAME]Could not open a database connection", ar.cause());
				message.fail(503, "Database unavailable: " + ar.cause());
			} else {
				SQLConnection connection = ar.result();
				connection.queryWithParams(SQL_SELECT_USER_BY_USERNAME, new JsonArray().add(username), query -> {
					connection.close();
					if (query.failed()) {
						LOGGER.error("[USER_SELECT_BY_USERNAME]Querying user for username " + username + " failed.",
								query.cause());
						message.fail(FailureCode.DB_ERROR.getCode(), query.cause().getMessage());

					} else {
						LOGGER.debug("[USER_SELECT_BY_USERNAME]Query successful");
						ResultSet resultSet = query.result();
						LOGGER.info("[USER_SELECT_BY_USERNAME]User found: " + resultSet.getNumRows());

						if (resultSet.getNumRows() != 0) {
							LOGGER.debug(resultSet.getRows().toString());
							message.reply(resultSet.getRows().get(0));
						}

						else{
							LOGGER.info("[USER_SELECT_BY_USERNAME]User not found.");
							message.reply(new JsonObject());
						}
					}
				});
			}
		});
	}

	/**
	 * DB operation to find a user by user id, reply a user json object which can be empty if the user is not found
	 * 
	 * @param message
	 */
	private void findUserById(Message<JsonObject> message) {

		String userId = message.body().getString("user_id");

		dbClient.getConnection(ar -> {
			if (ar.failed()) {
				LOGGER.error("[USER_SELECT_BY_USERID]Could not open a database connection", ar.cause());
				message.fail(503, "Database unavailable: " + ar.cause());
			} else {
				SQLConnection connection = ar.result();
				connection.queryWithParams(SQL_SELECT_USER_BY_USER_ID, new JsonArray().add(userId), query -> {
					connection.close();
					if (query.failed()) {
						LOGGER.error("[USER_SELECT_BY_USERID]Querying user for user id " + userId + " failed.",
								query.cause());
						message.fail(FailureCode.DB_ERROR.getCode(), query.cause().getMessage());

					} else {
						LOGGER.debug("[USER_SELECT_BY_USERID]Query successful");
						ResultSet resultSet = query.result();
						LOGGER.info("[USER_SELECT_BY_USERID]User found: " + resultSet.getNumRows());

						if (resultSet.getNumRows() != 0) {
							LOGGER.debug(resultSet.getRows().toString());
							message.reply(resultSet.getRows().get(0));
						}

						else{
							LOGGER.info("[USER_SELECT_BY_USEID]User not found.");
							message.reply(new JsonObject());
						}
					}
				});
			}
		});

	}

	/**
	 * DB operation to create a new authentication token for login with cookie, reply the id of the created token
	 * 
	 * @param message
	 */
	private void createAuthToken(Message<JsonObject> message) {
		String username = message.body().getString("username");
		String token = message.body().getString("auth_token");
		Long validTo = message.body().getLong("valid_to");

		String salt = authProvider.generateSalt();
		String hash = authProvider.computeHash(token, salt);

		MutableInt maxTokenId = new MutableInt(10000000);

		dbClient.getConnection(ar -> {
			if (ar.failed()) {
				LOGGER.error("[USER_TOKEN_CREATE]Could not open a database connection", ar.cause());
				message.fail(503, "Database unavailable: " + ar.cause());
			} else {
				SQLConnection connection = ar.result();

				connection.query(SQL_SELECT_MAX_TOKEN_ID, query -> {

					if (!query.result().getResults().get(0).hasNull(0))
						maxTokenId.setValue(Integer.valueOf(query.result().getResults().get(0).getString(0)));

					LOGGER.debug("[USER_TOKEN_CREATE]Max token id is :" + maxTokenId.getValue());

					connection.updateWithParams(SQL_INSERT_INTO_AUTH_TOKEN, new JsonArray()
																				.add(String.valueOf(maxTokenId.getValue() + 1))
																				.add(username)
																				.add(hash)
																				.add(salt)
																				.add(new java.sql.Timestamp(validTo).toString()),
							create -> {
								connection.close();
								if (create.failed()) {
									LOGGER.error("[USER_TOKEN_CREATE]Creating a new token for the user: " + username
											+ " failed.", create.cause());
									message.fail(FailureCode.DB_ERROR.getCode(), create.cause().getMessage());
								} else {

									if (create.result().getUpdated() != 0) {
										LOGGER.info("[USER_TOKEN_CREATE]" + create.result().getUpdated()
												+ " new token has been created for the user: " + username + " with id: "
												+ (maxTokenId.getValue() + 1));
										message.reply(maxTokenId.getValue() + 1);
									} else {
										LOGGER.info("[USER_TOKEN_CREATE]No token has been created");
										message.fail(FailureCode.DB_ERROR.getCode(), "No token has been created");
									}

								}
							});

				});
			}
		});
	}

	/**
	 * DB operation to delete a token, reply an information message
	 * 
	 * @param message
	 */
	private void deleteAuthToken(Message<JsonObject> message) {

		String tokenId = message.body().getString("token_id");

		dbClient.getConnection(ar -> {
			if (ar.failed()) {
				LOGGER.error("[AUTH_TOKEN_DELETE]Could not open a database connection", ar.cause());
				message.fail(503, "Database unavailable: " + ar.cause());
			} else {
				SQLConnection connection = ar.result();
				connection.updateWithParams(SQL_UPDATE_AUTH_TOKEN_SET_INVALID, new JsonArray().add(tokenId), delete -> {
					connection.close();
					if (delete.failed()) {
						LOGGER.error("[AUTH_TOKEN_DELETE]Deleting token: " + tokenId + " failed.", delete.cause());
						message.fail(FailureCode.DB_ERROR.getCode(), delete.cause().getMessage());

					} else {

						if (delete.result().getUpdated() != 0) {
							LOGGER.info("[AUTH_TOKEN_DELETE]Token with id : " + tokenId + " has been deleted.");
							message.reply("Token with id :" + tokenId + " has been deleted.");
						} else {
							LOGGER.info("[AUTH_TOKEN_DELETE]No token has been deleted.");
							message.fail(WarningCode.TOKEN_NOT_FOUND.getCode(), "Token for deletion not found.");
						}

					}
				});
			}
		});

	}

}