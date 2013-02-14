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
	private NotificationResult(
			final boolean initSuccess, 
			final String initMessage) {
		
		indicatesSuccess = initSuccess;
		message = initMessage;
	}
}
