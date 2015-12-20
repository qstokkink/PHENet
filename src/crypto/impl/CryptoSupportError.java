package crypto.impl;

/**
 * Some cryptographic implementations should be supported by the JVM.
 * If for some reason the JVM has a no implementation, a user should
 * not be running anything on it.
 */
public class CryptoSupportError extends Error{

	private static final long serialVersionUID = 917212650740283225L;

	public CryptoSupportError(String type){
		super(type + " is not supported by this JVM:" +
				"This JVM does not meet the requirements as specified by standards." +
				"Consider using another JVM."
				);
	}
	
}
