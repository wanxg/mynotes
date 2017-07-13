package com.wanxg.mynotes.util;

public enum FailureCode {

	NO_DB_KEY_SPECIFIED(900), BAD_DB_OPERATION(901), DB_ERROR(901),
	
	NO_USER_KEY_SPECIFIED(800), BAD_USER_ACTION(801), BAD_USER_SUB_ACTION(802), EVENTBUS_ERROR(803), EMAIL_ALREADY_EXISTS(804), ILLEGAL_ARGUMENT(805);

	private int code;

	FailureCode(int code) {
		this.code = code;
	}

	public int getCode() {
		return this.code;
	}
}
