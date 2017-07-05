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
	
	public static JDBCClient dbClient;
	public static JDBCAuth authProvider;

	
	private static final String SQL_CREATE_TABLE_USER = "CREATE TABLE IF NOT EXISTS user ("
			+ "username varchar(255) NOT NULL PRIMARY KEY, " + "fullname varchar(255) NOT NULL, "
			+ "password varchar(255) NOT NULL, " + "password_salt varchar(255) NOT NULL)";

	private static final String SQL_CREATE_TABLE_USER_ROLE = "CREATE TABLE IF NOT EXISTS user_role ("
			+ "username varchar(255) NOT NULL, " + "role varchar(255) NOT NULL, " + "PRIMARY KEY (username,role))";

	private static final String SQL_CREATE_TABLE_ROLE_PERM = "CREATE TABLE IF NOT EXISTS role_perm ("
			+ "role varchar(255) NOT NULL PRIMARY KEY, " + "permission varchar(255) NOT NULL)";

	private static final String SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_USERNAME = "ALTER TABLE user_role ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_username FOREIGN KEY (username) REFERENCES user(username)";

	private static final String SQL_ALTER_TABLE_USER_ROLE_ADD_CONSTRAINT_FOREIGN_KEY_ROLE = "ALTER TABLE user_role ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_role FOREIGN KEY (role) REFERENCES role_perm(role)";

	private static final String SQL_SELECT_USER_BY_USERNAME = "SELECT username FROM user WHERE username = ?";
	
	private static final String SQL_INSERT_INTO_USER = "INSERT INTO user VALUES (?,?,?,?)";
	
	
	
	@Override
	public void start(Future<Void> startFuture) throws Exception {

		LOGGER.info("Starting DatabaseVerticle ...");

		dbClient = JDBCClient.createShared(vertx, new JsonObject().put("url", "jdbc:hsqldb:file:db/wiki")
				.put("driver_class", "org.hsqldb.jdbcDriver").put("max_pool_size", 30));

		dbClient.getConnection(ar -> {
			if (ar.failed()) {
				LOGGER.error("Could not open a database connection", ar.cause());
				startFuture.fail(ar.cause());
			} else {

				SQLConnection connection = ar.result();
				List<String> sqlStatements = Arrays.asList(SQL_CREATE_TABLE_USER, SQL_CREATE_TABLE_USER_ROLE,
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
		
		switch(actionCode){
		
			case USER_CREATE:
				
				String salt = authProvider.generateSalt();
				String hash = authProvider.computeHash(message.body().getString("password"), salt);

				System.out.println("salt: " + salt);
				System.out.println("hash: " + hash);
				
				dbClient.getConnection(ar -> {
					if (ar.failed()) {
						LOGGER.error("Could not open a database connection", ar.cause());
					} else {
						SQLConnection connection = ar.result();
						connection.updateWithParams(SQL_INSERT_INTO_USER,
								new JsonArray().add(message.body().getString("username"))
										.add(message.body().getString("fullname")).add(hash).add(salt),
								res -> {
									connection.close();
									if (res.failed()) {
										LOGGER.error("[USER_CREATE]Creating new user failed.", res.cause());
										message.fail(FailureCode.DB_ERROR.getCode(), res.cause().getMessage());
									} else {
										LOGGER.info("[USER_CREATE]New user has been created.");
									}
								});
					}
				});
				
				break;
			
			case USER_FIND:
				/*
				 * DB operation to check if a user exists identified by the username.
				 */
				String username = message.body().getString("username");
				
				dbClient.getConnection(ar -> {
					if (ar.failed()) {
						LOGGER.error("Could not open a database connection", ar.cause());
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
								LOGGER.debug("[USER_FIND]User found : " + resultSet.getNumRows());
								
								if(resultSet.getNumRows()!=0)
									message.reply(new JsonObject().put("userExists", true));
									
								else
									message.reply(new JsonObject().put("userExists", false));
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