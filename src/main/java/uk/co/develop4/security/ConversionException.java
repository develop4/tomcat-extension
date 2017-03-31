package uk.co.develop4.security;

public class ConversionException extends Exception {

	private static final long serialVersionUID = 1L;

	public ConversionException() {
	}

	public ConversionException(String message) {
		super(message);
	}

	public ConversionException(Throwable cause) {
		super(cause);
	}

	public ConversionException(String message, Throwable cause) {
		super(message, cause);
	}

	public ConversionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
