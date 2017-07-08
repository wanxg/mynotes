package com.wanxg.mynotes.database;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wanxg.mynotes.FailureCode;
import com.wanxg.mynotes.EventBusAddress;

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
	private static long auth_token_id = 10000;
	
	public static JDBCClient dbClient;
	public static JDBCAuth authProvider;
	
	
	private static final String SQL_CREATE_TABLE_USER = "CREATE TABLE IF NOT EXISTS user ("
			+ "user_id varchar(255) NOT NULL, username varchar(255) NOT NULL PRIMARY KEY, " + "fullname varchar(255) NOT NULL, "
			+ "password varchar(255) NOT NULL, " + "password_salt varchar(255) NOT NULL);";

	
	private static final String SQL_CREATE_TABLE_AUTH_TOKEN = "CREATE TABLE IF NOT EXISTS auth_token ("
			+ "id varchar(10) NOT NULL, "
			+ "username varchar(255) NOT NULL, "
			+ "token varchar(255) NOT NULL, "
			+ "token_salt varchar(255) NOT NULL, "
			+ "PRIMARY KEY (username,token));";
	
	private static final String SQL_ALTER_TABLE_AUTH_TOKEN_ADD_CONSTRAINT_FOREIGN_KEY_USERNAME = "ALTER TABLE auth_token ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_auth_token_username FOREIGN KEY (username) REFERENCES user(username)";
	
	
	private static final String SQL_CREATE_TABLE_USER_ROLE = "CREATE TABLE IF NOT EXISTS user_role ("
			+ "username varchar(255) NOT NULL, " + "role varchar(255) NOT NULL, " + "PRIMARY KEY (username,role))";

	private static final String SQL_CREATE_TABLE_ROLE_PERM = "CREATE TABLE IF NOT EXISTS role_perm ("
			+ "role varchar(255) NOT NULL PRIMARY KEY, " + "permission varchar(255) NOT NULL)";

	private static final String SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_USERNAME = "ALTER TABLE user_role ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_user_role_username FOREIGN KEY (username) REFERENCES user(username)";

	private static final String SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_ROLE = "ALTER TABLE user_role ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_user_role_role FOREIGN KEY (role) REFERENCES role_perm(role)";

	private static final String SQL_SELECT_USER_BY_USERNAME = "SELECT * FROM user WHERE username = ?";
	
	private static final String SQL_INSERT_INTO_USER = "INSERT INTO user VALUES (?,?,?,?,?)";
	
	private static final String SQL_INSERT_INTO_AUTH_TOKEN = "INSERT INTO auth_token VALUES (?,?,?,?)";
	
	public static final String SQL_SELECT_AUTH_TOKEN_BY_USER_ID_AND_TOKEN_ID = 
			"SELECT token, token_salt FROM auth_token LEFT JOIN user ON auth_token.username = user.username WHERE user.user_id = ? AND auth_token.id = ?";
	
	public static final String AUTHENTICATE_QUERY_FOR_TOKEN = "SELECT token, token_salt FROM auth_token WHERE id=?";
	
	
	@Override
	public void start(Future<Void> startFuture) throws Exception {

		LOGGER.info("Starting DatabaseVerticle ...");

		dbClient = JDBCClient.createShared(vertx, new JsonObject().put("url", "jdbc:hsqldb:file:db/mynotesdb")
				.put("driver_class", "org.hsqldb.jdbcDriver").put("max_pool_size", 30));

		dbClient.getConnection(ar -> {
			if (ar.failed()) {
				LOGGER.error("Could not open a database connection", ar.cause());
				startFuture.fail(ar.cause());
			} else {

				SQLConnection connection = ar.result();
				List<String> sqlStatements = Arrays.asList(SQL_CREATE_TABLE_USER, 
						SQL_CREATE_TABLE_AUTH_TOKEN, SQL_ALTER_TABLE_AUTH_TOKEN_ADD_CONSTRAINT_FOREIGN_KEY_USERNAME,
						SQL_CREATE_TABLE_USER_ROLE, SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_USERNAME, 
						SQL_CREATE_TABLE_ROLE_PERM, SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_ROLE);

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
		String username,salt,hash,token,userId,tokenId;
		
		switch(actionCode){
		
			case USER_CREATE:
				
				username = message.body().getString("username");
				salt = authProvider.generateSalt();
				hash = authProvider.computeHash(message.body().getString("password"), salt);

				System.out.println("salt: " + salt);
				System.out.println("hash: " + hash);
				
				dbClient.getConnection(ar -> {
					if (ar.failed()) {
						LOGGER.error("Could not open a database connection", ar.cause());
					} else {
						SQLConnection connection = ar.result();
						connection.updateWithParams(SQL_INSERT_INTO_USER,
								new JsonArray()
									.add(authProvider.computeHash(username, salt))
									.add(username)
									.add(message.body().getString("fullname"))
									.add(hash)
									.add(salt),
								res -> {
									connection.close();
									if (res.failed()) {
										LOGGER.error("[USER_CREATE]Creating new user failed.", res.cause());
										message.fail(FailureCode.DB_ERROR.getCode(), res.cause().getMessage());
									} else {
										LOGGER.info("[USER_CREATE]New user has been created.");
										message.reply("User: " + username + " has been created" );
										
									}
								});
					}
				});
				
				break;
			
			case USER_SELECT_BY_USERNAME:
				/*
				 * DB operation to check if a user exists identified by the username.
				 */
				username = message.body().getString("username");
				
				dbClient.getConnection(ar -> {
					if (ar.failed()) {
						LOGGER.error("Could not open a database connection", ar.cause());
						message.fail(503, "Database unavailable: " + ar.cause());
					} else {
						SQLConnection connection = ar.result();
						connection.queryWithParams(SQL_SELECT_USER_BY_USERNAME, new JsonArray().add(username), query->{
							connection.close();
							if (query.failed()) {
								LOGGER.error("[USER_FIND]Querying user for username " + username +" failed.", query.cause());
								message.fail(FailureCode.DB_ERROR.getCode(), query.cause().getMessage());
								
							} else {
								LOGGER.debug("[USER_FIND]Query successful");
								ResultSet resultSet = query.result();
								LOGGER.info("[USER_FIND]User found : " + resultSet.getNumRows());
								
								if(resultSet.getNumRows()!=0){
									LOGGER.debug(resultSet.getRows().toString());
									message.reply(resultSet.getRows().get(0));
								}
									
								else
									message.reply(new JsonObject());
							}
						});
					}
				});
				
				break;
			
			case USER_TOKEN_CREATE:	
				
				username = message.body().getString("username");
				token = message.body().getString("auth_token");
				
				salt = authProvider.generateSalt();
				hash = authProvider.computeHash(token, salt);
				
				dbClient.getConnection(ar -> {
					if (ar.failed()) {
						LOGGER.error("Could not open a database connection", ar.cause());
						message.fail(503, "Database unavailable: " + ar.cause());
					} else {
						SQLConnection connection = ar.result();
						connection.updateWithParams(SQL_INSERT_INTO_AUTH_TOKEN,
								new JsonArray()
									.add(String.valueOf(auth_token_id++))
									.add(username)
									.add(hash)
									.add(salt),
								res -> {
									connection.close();
									if (res.failed()) {
										LOGGER.error("[USER_TOKEN_CREATE]Creating a new token for the user: " +username+" failed.", res.cause());
										message.fail(FailureCode.DB_ERROR.getCode(), res.cause().getMessage());
									} else {
										LOGGER.info("[USER_TOKEN_CREATE]A new token has been created for the user: " +username);
										message.reply(auth_token_id-1);
									}
								});
					}
				});
				
				break;
			
			case AUTH_TOKEN_SELECT_BY_USERID_TOKENID:	
				
				userId = message.body().getString("user_id");
				tokenId = message.body().getString("token_id");
				
				dbClient.getConnection(ar -> {
					if (ar.failed()) {
						LOGGER.error("Could not open a database connection", ar.cause());
						message.fail(503, "Database unavailable: " + ar.cause());
					} else {
						SQLConnection connection = ar.result();
						connection.queryWithParams(SQL_SELECT_AUTH_TOKEN_BY_USER_ID_AND_TOKEN_ID,
								new JsonArray()
									.add(userId)
									.add(tokenId),
								query -> {
									connection.close();
									if (query.failed()) {
										LOGGER.error("[AUTH_TOKEN_SELECT_BY_USERID_TOKENID]Searching for tokens for the user: " +userId+" failed.", query.cause());
										message.fail(FailureCode.DB_ERROR.getCode(), query.cause().getMessage());
									} else {
										LOGGER.debug("[AUTH_TOKEN_SELECT_BY_USERID_TOKENID]Query successful");
										ResultSet resultSet = query.result();
										LOGGER.info("[AUTH_TOKEN_SELECT_BY_USERID_TOKENID]Token(s) found:  " + resultSet.getNumRows());
										if(resultSet.getNumRows()==1){
											LOGGER.debug("[AUTH_TOKEN_SELECT_BY_USERID_TOKENID]"+resultSet.getRows().toString());
											//message.reply(new JsonObject().put("token_list", resultSet.getRows()));
											message.reply(resultSet.getRows().get(0));
										}
										else
											message.reply(new JsonObject());
									}
								});
					}
				});
				
				break;
				
			default:
				message.fail(FailureCode.BAD_DB_OPERATION.getCode(), "Bad database operation: " + actionCode);
		}

	}
	
}