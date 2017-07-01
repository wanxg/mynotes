package com.wanxg.mynotes;

import com.wanxg.mynotes.core.UserManagerVerticle;
import com.wanxg.mynotes.database.DatabaseVerticle;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Vertx;

public class MainVerticle extends AbstractVerticle {

	public static void main(String[] args) {

		System.setProperty("vertx.disableFileCaching", "true");

		Vertx vertx = Vertx.vertx();

		vertx.deployVerticle(new MainVerticle());

	}

	@Override
	public void start(Future<Void> startFuture) throws Exception {

		Future<String> databaseDeployment = Future.future();

		vertx.deployVerticle(new DatabaseVerticle(), databaseDeployment.completer());

		databaseDeployment.compose(id -> {

			Future<String> userManagerDeployment = Future.future();
			
			vertx.deployVerticle(new UserManagerVerticle(), userManagerDeployment.completer());
			
			return userManagerDeployment;

		}).compose(id -> {
			
			Future<String> httpServerDeployment = Future.future();

			vertx.deployVerticle("com.wanxg.mynotes.http.HttpServerVerticle", new DeploymentOptions().setInstances(4),
					httpServerDeployment.completer());

			return httpServerDeployment;
			
		}).setHandler(ar -> {

			if (ar.succeeded()) {
				startFuture.complete();
			} else {
				startFuture.fail(ar.cause());
			}

		});
	}

}
