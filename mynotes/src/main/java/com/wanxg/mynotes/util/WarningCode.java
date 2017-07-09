package com.wanxg.mynotes.util;

public enum WarningCode {

	TOKEN_CREATION_FAILED(700), USER_NOT_FOUND(701), TOKEN_NOT_FOUND(702);

	private int code;

	WarningCode(int code) {
		this.code = code;
	}

	public int getCode() {
		return this.code;
	}
}
