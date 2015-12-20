package net.payload;

/**
 * Thrown when a packet is deemed malformed
 */
public class IllegalPacketException extends Exception{

	private static final long serialVersionUID = 3419771532976369554L;

	public IllegalPacketException(String message){
		super(message);
	}
	
}
