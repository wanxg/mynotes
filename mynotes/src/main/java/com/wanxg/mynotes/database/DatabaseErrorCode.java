package com.wanxg.mynotes.database;

public enum DatabaseErrorCode {

	NO_DB_KEY_SPECIFIED(100), BAD_DB_OPERATION(101), DB_ERROR(102);

	int code;

	DatabaseErrorCode(int code) {
		this.code = code;
	}

	int getCode() {
		return this.code;
	}
}
