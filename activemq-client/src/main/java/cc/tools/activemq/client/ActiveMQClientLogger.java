package cc.tools.activemq.client;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;

/**
 * This class implements logging.
 * 
 * @author cc
 * @version %I%, %G%
 * @since 0.1
 */
public class ActiveMQClientLogger {

  /**
   * Constructor {@link ActiveMQClientLogger}.
   * @param name String containing logger name. 
   */
  public ActiveMQClientLogger(String name) {
    _name = name;
  }

  /**
   * Method output info level text.
   * @param t String to be output.
   */
  public void info(String t) {
    System.out.print(this.prefix());
    System.out.print(_info);    
    System.out.println(t);    
  }
 
  /**
   * Method output info level text.
   * @param ts Strings to be output.
   */
  public void info(String ...  ts) {
    System.out.print(this.prefix());
    System.out.print(_info);    

    for (String t : ts) {
      System.out.print(t);
    }
    
    System.out.println("");
  }

  /**
   * Method output info level text.
   * @param os objects to be output.
   */
  public void info(Object ...  os) {
    System.out.print(this.prefix());
    System.out.print(_info);    

    for (Object o : os) {
      System.out.print(o.toString());
    }
    
    System.out.println("");
  }
  
  // 
  
  /**
   * Method output error level text.
   * @param t String to be output.
   */
  public void error(String t) {
    System.out.print(this.prefix());
    System.out.print(_error);    
    System.out.println(t);    
  }

  /**
   * Method output error level text.
   * @param ts Strings to be output.
   */
  public void error(String ...  ts) {
    System.out.print(this.prefix());
    System.out.print(_error);    
    
    for (String t : ts) {
      System.out.print(t);
    }
    
    System.out.println("");    
  }

  /**
   * Method output error level text.
   * @param os objects to be output.
   */
  public void error(Object ...  os) {
    System.out.print(this.prefix());
    System.out.print(_error);    

    for (Object o : os) {
      System.out.print(o.toString());
    }
    
    System.out.println("");
  }

  // 
  
  /**
   * Method output exception level text.
   * @param e Exception to be output.
   */
  public void exception(Exception e) {
    System.out.print(this.prefix());
    System.out.print(_exception);    
    System.out.print(e.toString());
    System.out.print(" ");
    System.out.println(getStackTraceAsString(e));
  }
  
  /**
   * Method output log line prefix.
   * @return String containing output prefix.
   */
  private String prefix() {
    return new Date().toString() + 
        " " +
        _name;
  }
  
  /**
   * Method returns a String containing stack trace from Throwable parameter t.
   * 
   * @param t {@link java.lang.Throwable} object containing stack trace
   * @return String containing stack trace of throwable parameter
   */
  private String getStackTraceAsString(Throwable t) {

    StringWriter stringWriter = new StringWriter();
    
    PrintWriter printWriter = new PrintWriter(stringWriter, true);

    t.printStackTrace(printWriter);

    return stringWriter.getBuffer().toString();
  }
  
  /**
   * Output level text for error.
   */
  private String _error = " error: ";
  
  /**
   * Output level text for info.
   */
  private String _info = " info: ";

  /**
   * Output level text for exception.
   */
  private String _exception = " exception: ";

  /**
   * Logger name. Normally owning class name.
   */
  private String _name = null;
}