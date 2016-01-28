/*
 * Copyright 2013 Georg Gruetter
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jenkinsci.plugins.stashNotifier;

/**
 * convenience class to capture the result of a notification.
 */
public final class NotificationResult {
	
	/** true if and only if the notification was successful. */
	public final boolean indicatesSuccess;
	
	/** 
	 * the error message in case the notification was not succesful or
	 * null, otherwise.
	 */
	public final String message;
	
	/**
	 * returns a new NotificationResult instance indicating a successful
	 * notification.
	 * 
	 * @return a new NotificationResult instance indicating a successful
	 * notification
	 */
	public static NotificationResult newSuccess() {
		return new NotificationResult(true, null);
	}
	
	/**
	 * returns a new NotificationResult instance indicating a failed
	 * notification.
	 * 
	 * @param	message	the message indicating why the notifiation failed
	 * @return  a new NotificationResult instance indicating a successful
	 * 			notification
	 */		
	public static NotificationResult newFailure(String message) {
		return new NotificationResult(false, message);
	}
	
	/**
	 * default constructor
	 * 
	 * @param initSuccess	success flag
	 * @param initMessage 	message in case notification was not successful
	 */
	protected NotificationResult(
			final boolean initSuccess, 
			final String initMessage) {
		
		indicatesSuccess = initSuccess;
		message = initMessage;
	}
}
