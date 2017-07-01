package com.wanxg.mynotes;

public enum EventBusAddress {
	
	
	USER_MANAGER_QUEUE_ADDRESS("mynote.usermanager.queue"),
	DB_QUEUE_ADDRESS("mynote.dbqueue");
	
	
	private String address;
	
	private EventBusAddress(String address){
		this.address = address;
	}
	
	public String getAddress(){
		return this.address;
	}
}
