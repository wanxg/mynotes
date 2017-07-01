package com.wanxg.mynotes.database;

import java.util.Arrays;
import java.util.List;

import com.wanxg.mynotes.EventBusAddress;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

public class DatabaseVerticle extends AbstractVerticle {

	private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseVerticle.class);
	private JDBCClient dbClient;
	private JDBCAuth authProvider;

	
	private static final String SQL_CREATE_TABLE_USERS = "CREATE TABLE IF NOT EXISTS users ("
			+ "email varchar(255) NOT NULL PRIMARY KEY, " + "username varchar(255) NOT NULL, "
			+ "password varchar(255) NOT NULL, " + "password_salt varchar(255) NOT NULL)";

	private static final String SQL_CREATE_TABLE_USER_ROLES = "CREATE TABLE IF NOT EXISTS user_roles ("
			+ "email varchar(255) NOT NULL, " + "role varchar(255) NOT NULL, " + "PRIMARY KEY (email,role))";

	private static final String SQL_CREATE_TABLE_ROLE_PERMS = "CREATE TABLE IF NOT EXISTS role_perms ("
			+ "role varchar(255) NOT NULL PRIMARY KEY, " + "permission varchar(255) NOT NULL)";

	private static final String SQL_ALTER_TABLE_USER_ROLES_ADD_CONSTRAINT_FOREIGN_KEY_EMAIL = "ALTER TABLE user_roles ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_email FOREIGN KEY (email) REFERENCES users(email)";

	private static final String SQL_ALTER_TABLE_USER_ROLES_ADD_CONSTRAINT_FOREIGN_KEY_ROLE = "ALTER TABLE user_roles ADD CONSTRAINT IF NOT EXISTS "
			+ "fk_role FOREIGN KEY (role) REFERENCES role_perms(role)";

	private static final String SQL_SELECT_USER_BY_EMAIL = "SELECT email FROM users WHERE email = ?";
	
	private static final String SQL_INSERT_INTO_USER = "INSERT INTO users VALUES (?,?,?,?)";
	
	
	
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
				List<String> sqlStatements = Arrays.asList(SQL_CREATE_TABLE_USERS, SQL_CREATE_TABLE_USER_ROLES,
						SQL_ALTER_TABLE_USER_ROLES_ADD_CONSTRAINT_FOREIGN_KEY_EMAIL, SQL_CREATE_TABLE_ROLE_PERMS,
						SQL_ALTER_TABLE_USER_ROLES_ADD_CONSTRAINT_FOREIGN_KEY_ROLE);

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
			message.fail(DatabaseErrorCode.NO_DB_KEY_SPECIFIED.getCode(), "No db key specified in the msg header.");
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
								new JsonArray().add(message.body().getString("email"))
										.add(message.body().getString("username")).add(hash).add(salt),
								res -> {
									connection.close();
									if (res.failed()) {
										LOGGER.error("[USER_CREATE]Creating new user failed.", res.cause());
										message.fail(DatabaseErrorCode.DB_ERROR.getCode(), res.cause().getMessage());
									} else {
										LOGGER.info("[USER_CREATE]New user has been created.");
									}
								});
					}
				});
				
				break;
			
			case USER_FIND:
				/*
				 * DB operation to check if a user exists identified by an email address.
				 */
				String email = message.body().getString("email");
				
				dbClient.getConnection(ar -> {
					if (ar.failed()) {
						LOGGER.error("Could not open a database connection", ar.cause());
					} else {
						SQLConnection connection = ar.result();
						connection.queryWithParams(SQL_SELECT_USER_BY_EMAIL, new JsonArray().add(email), query->{
							connection.close();
							if (query.failed()) {
								LOGGER.error("[USER_FIND]Querying user for email " + email +" failed.", query.cause());
								message.fail(DatabaseErrorCode.DB_ERROR.getCode(), query.cause().getMessage());
								
							} else {
								LOGGER.info("[USER_FIND]OK");
								ResultSet resultSet = query.result();
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
				message.fail(DatabaseErrorCode.BAD_DB_OPERATION.getCode(), "Bad database operation: " + actionCode);
		}


	}
	
}