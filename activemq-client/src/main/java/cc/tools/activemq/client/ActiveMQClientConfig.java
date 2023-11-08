package cc.tools.activemq.client;

import java.util.*;

/**
 * This class manages program command line parameters and configuration values
 * 
 * @author cc
 * @version %I%, %G%
 * @since 0.1
 */
public class ActiveMQClientConfig extends ActiveMQClientValues {

  /**
   * Enum VALUES_STATUS is used to indicate the status of the value object during
   * processing.
   */
  static public enum VALUES_STATUS {
    /**
     * Status value {@link VALUES_STATUS_OK} means 'Ok'
     */
    VALUES_STATUS_OK,
    /**
     * Status value {@link VALUES_STATUS_HELP} means 'Help'
     */
    VALUES_STATUS_HELP,
    /**
     * Status value {@link VALUES_STATUS_ERROR} means 'Error'
     */
    VALUES_STATUS_ERROR
  };

  /**
   * Constructor for {@link ActiveMQClientConfig}.
   * 
   * @param args command line array containing parameter values.
   */
  public ActiveMQClientConfig(String[] args) {

    super();

    super.load(args);

    if (getStatus() == ActiveMQClientConfig.VALUES_STATUS.VALUES_STATUS_OK) {
      _isValid = true;
    }

  }

  /**
   * Method displays table showing configured values.
   */
  public void doDump() {
    _logger.info("configuration:");
    _logger.info("-protocol:           " + getProtocol());
    _logger.info("-hostname:           " + getHostname());
    _logger.info("-port:               " + getPort());
    _logger.info("-url:                " + getURL());
    _logger.info("-client-private-key: " + getClientPrivateKeyFile());
    _logger.info("-client-public-key:  " + getClientPublicKeyFile());
    _logger.info("-server-public-key:  " + getServerPublicKeyFile());
    _logger.info("-message:            " + getMessage());
    _logger.info("-channel:            " + getChannel());
    _logger.info("-credentials:        " + getCredentials());
    _logger.info("-count:              " + getCount());
    _logger.info("-sleep:              " + getSleep());
    _logger.info("-unique:             " + (getUnique() ? "true" : "false"));
    _logger.info("-debug:              " + (getDebug() ? "true" : "false"));
  }

  /**
   * Method displays 'usage' help information showing command-line options.
   */
  public void doHelp() {
    _logger.info("usage:");
    _logger.info(" [-protocol (http|https)] -hostname (ip|domain) [-port <port>] [-url <path>] ");
    _logger.info("-client-private-key <file> -client-public-key <file> -server-public-key <file> -message <xml-message> ");
    _logger.info("-channel <channel name> -credentials <file> [-count <ms>] [-sleep <ms>] [-unique] [-debug]");
    _logger.info("-protocol:           optional.  set to http or https. default https.");
    _logger.info("-hostname:           mandatory. server host. can be an ip address or name.");
    _logger.info("-port:               optional.  server port. default 80/443 based on protocol.");
    _logger.info("-url:                optional.  url server endpoint prefix. default '/ipserver/server/ip'.");
    _logger.info("-client-private-key: mandatory. client's private key file.");
    _logger.info("-client-public-key:  mandatory. client's public key file.");
    _logger.info("-server-public-key:  mandatory. server's public key file.");
    _logger.info("-message:            mandatory. log message to send to server.");
    _logger.info("-channel:            mandatory. channel lookup on broker to publish messages to.");
    _logger.info("-credentials:        mandatory. credentials for server access.");
    _logger.info("-count:              optional.  number of messages to be sent to server.");
    _logger.info("-sleep:              optional.  sleep pause (in ms) between log commands to server.");
    _logger.info("-unique:             optional.  toggle flag to generate individual messages based on value in -message field. default false.");
    _logger.info("-debug:              optional.  toggle flag to adjust debug mode. default false.");
  }

  /**
   * Method returns {@code List<String>} containing configuration errors.
   * 
   * @return {@code List<String>} containing configuration errors.
   */
  public List<String> getErrors() {
    return _errors;
  }

  /**
   * Method returns boolean indicating whether command line parameters include
   * help '-h' flag.
   * 
   * @return boolean indicating whether help command line option is present.
   */
  public boolean getIsHelp() {
    return getStatus() == ActiveMQClientConfig.VALUES_STATUS.VALUES_STATUS_HELP;
  }

  /**
   * Method returns {@link #_isValid} value.
   * 
   * @return boolean indicating whether configuration is valid or not.
   */
  public boolean isValid() {
    return _isValid;
  }

  /**
   * Configured flag indicating whether {@link ActiveMQClientConfig} is valid or
   * not.
   */
  private boolean _isValid = false;
  
  /**
   * Local logger reference for logging operations.
   */
  final private static ActiveMQClientLogger _logger = new ActiveMQClientLogger(ActiveMQClientConfig.class.getName());
}
