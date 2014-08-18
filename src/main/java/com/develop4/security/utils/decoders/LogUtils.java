package com.develop4.security.utils.decoders;

public class LogUtils {
	
	private String name;
	
	private Boolean debug = false; 
	private Boolean warn = true; 
	private Boolean info = true; 
	private Boolean fatal = true; 
	
	public LogUtils(String name) {
		this.name = name;
	}
	public static LogUtils getLog(Class myclass){
		return new LogUtils(myclass.getName());
	}
	
	public void info(final String message){
		System.out.println("INFO: " + name + "\t" + message);
	}
	
	public void warn(final String message){
		System.out.println("WARN: " + name + "\t" + message);
	}
	
	public void debug(final String message){
		System.out.println("DEBUG: " + name + "\t" + message);
	}
	
	public void error(final String message){
		System.out.println("ERROR: " + name + "\t" + message);
	}
	
	public void fatal(final String message, final Exception ex){
		System.out.println("FATAL: " + name + "\t" + message + " \t " + ex.getMessage());
	}
	
	public void fatal(final String message){
		System.out.println("FATAL: " + name + "\t" + message);
	}
	
	public boolean isDebugEnabled() {
		return debug;
	}
	
	public boolean isWarnEnabled() {
		return debug;
	}
	
	public boolean isInfoEnabled() {
		return info;
	}
	
	

}
