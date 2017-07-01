package com.wanxg.mynotes.core;

public enum UserManagerErrorCode {

	NO_USER_KEY_SPECIFIED(200), BAD_USER_ACTION(201), EVENTBUS_ERROR(202), EMAIL_ALREADY_EXISTS(203);

	private int code;

	UserManagerErrorCode(int code) {
		this.code = code;
	}

	public int getCode() {
		return this.code;
	}
}
