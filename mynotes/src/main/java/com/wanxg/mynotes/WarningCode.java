package com.wanxg.mynotes;

public enum WarningCode {

	TOKEN_CREATION_FAILED(700),TOKEN_NOT_FOUND(701);

	private int code;

	WarningCode(int code) {
		this.code = code;
	}

	public int getCode() {
		return this.code;
	}
}
