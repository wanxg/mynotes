package com.wanxg.mynotes;

import static io.vertx.ext.sync.Sync.awaitResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import co.paralleluniverse.fibers.Suspendable;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;
import io.vertx.ext.sync.SyncVerticle;

public class TestVerticle extends SyncVerticle {

	private static final String SQL_SELECT_USER_BY_USERNAME = "SELECT * FROM user WHERE username = ?";
	private static final Logger LOGGER = LoggerFactory.getLogger(TestVerticle.class);

	public static void main(String[] args) {
		Vertx vertx = Vertx.vertx();
		vertx.deployVerticle(new TestVerticle());
	}

	@Override
	@Suspendable
	public void start() throws Exception {

		System.out.println("Starting DatabaseVerticle ...");

		JDBCClient dbClient = JDBCClient.createShared(vertx,
				new JsonObject().put("url", "jdbc:hsqldb:hsql://localhost/xdb")
						.put("driver_class", "org.hsqldb.jdbcDriver").put("max_pool_size", 30));

		
		String username = "wanxiaolong@gmail.com";
		
		try (SQLConnection conn = awaitResult(dbClient::getConnection)) {

			ResultSet res = awaitResult(
					h -> conn.queryWithParams(SQL_SELECT_USER_BY_USERNAME, new JsonArray().add(username), h));
			LOGGER.info("[USER_SELECT_BY_USERNAME]User found: " + res.getNumRows());
			if (res.getNumRows() != 0) {
				LOGGER.debug(res.getRows().toString());

			} else {
				LOGGER.info("[USER_SELECT_BY_USERNAME]User not found.");
			}
		}

	}

}
