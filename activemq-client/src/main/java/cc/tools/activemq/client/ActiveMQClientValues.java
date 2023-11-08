package cc.tools.activemq.client;

import java.util.*;

/**
 * This encapsulates Parameter key values
 * 
 * @author cc
 * @version %I%, %G%
 * @since 0.1
 */
public class ActiveMQClientValues {

  /**
   * Constructor for {@link ActiveMQClientValues}.
   */
  public ActiveMQClientValues() {
  }

  /**
   * Method loads parameter settings from command line arguments.
   * 
   * @param args String array containing command line arguments.
   */
  void load(String[] args) {

    Map<String, String> values = new HashMap<String, String>();

    _status = ActiveMQClientParameterKeys.load(args, values, _errors);

    if (_status != ActiveMQClientConfig.VALUES_STATUS.VALUES_STATUS_OK) {
      
      return;
    
    }

    if (!setValues(values)) {
    
      _status = ActiveMQClientConfig.VALUES_STATUS.VALUES_STATUS_ERROR;
      
      return;
    }

    _status = ActiveMQClientConfig.VALUES_STATUS.VALUES_STATUS_OK;
  }

  /**
   * Method returns the status of {@link ActiveMQClientConfig} object.
   * 
   * @return {@link Enum} {@link ActiveMQClientConfig.VALUES_STATUS} value
   *         indicating status.
   */
  public ActiveMQClientConfig.VALUES_STATUS getStatus() {
    return _status;
  }

  /**
   * Method loads configuration from file and returns boolean indicating result of
   * loading and processing command line arguments.
   * 
   * @param values {@code Map<String, String>} containing command line name/value
   *               pairs.
   * 
   * @return boolean indicating whether load was successful.
   */
  private boolean setValues(Map<String, String> values) {

    if (!setClientPrivateKeyFile(values) | !setClientPublicKeyFile(values) | !setDebug(values) | !setHostname(values)
        | !setProtocol(values) | !setPort(values) | !setServerPublicKeyFile(values) | !setCredentials(values)
        | !setMessage(values) | !setCount(values) | !setSleep(values) | !setURL(values) | !setUnique(values) | !setChannel(values) ) {

      return false;

    }

    Set<String> inKeys = new HashSet<String>(values.keySet());
    Set<String> outKeys = new HashSet<String>(Arrays.asList(ActiveMQClientParameterKeys._KEYS));

    inKeys.removeAll(outKeys);
    outKeys.removeAll(values.keySet());

    if (inKeys.isEmpty() && outKeys.isEmpty()) {
      return true;
    }

    for (String key : inKeys) {
      _errors.add("parameter not recognized '" + key + "'");
    }

    for (String key : outKeys) {
      _errors.add("parameter not set '" + key + "'");
    }

    return false;
  }

  /**
   * Method to store 'mandatory parameter missing' error.
   * 
   * @param parameterName name of parameter to report.
   */
  private void logMissingParameterError(String parameterName) {
    
    StringBuilder buffer = new StringBuilder();
    
    buffer.append("mandatory parameter -");
    buffer.append(parameterName);
    buffer.append(" missing");
    
    _errors.add(buffer.toString());
  }

  /**
   * Method returns {@link #_clientPrivateKeyFile} filename configuration value.
   * 
   * @return {@link String} containing configured -client-private-key value.
   */
  protected String getClientPrivateKeyFile() {
    return _clientPrivateKeyFile;
  }

  /**
   * Method returns {@link #_clientPublicKeyFile} filename configuration value.
   * 
   * @return {@link String} containing configured -client-public-key value.
   */
  protected String getClientPublicKeyFile() {
    return _clientPublicKeyFile;
  }

  /**
   * Method returns {@link #_credentials} filename onfiguration value.
   * 
   * @return {@link String} containing -credentials string.
   */
  protected String getCredentials() {
    return _credentials;
  }

  /**
   * Method returns {@link #_debug} configuration value.
   * 
   * @return boolean indicating whether debug mode is on or not.
   */
  protected boolean getDebug() {
    return _debug;
  }

  /**
   * Method returns {@link #_hostname} configuration value.
   * 
   * @return {@link String} containing parameter -hostname value.
   */
  protected String getHostname() {
    return _hostname;
  }

  /**
   * Method returns the {@link #_message} configuration value.
   * 
   * @return String message to be sent to server.
   */
  protected String getMessage() {
    return _message;
  }

  /**
   * Method returns the {@link #_channel} configuration value.
   * 
   * @return String channel name to be sent to server.
   */
  protected String getChannel() {
    return _channel;
  }

  /**
   * Method returns the {@link #_unique} configuration value.
   * 
   * @return boolean unique flag to be sent to server.
   */
  protected boolean getUnique() {
    return _unique;
  }

  /**
   * Method returns the {@link #_count} configuration value.
   * 
   * @return count of the number of messages to send to the server..
   */
  protected int getCount() {
    return _count;
  }

  /**
   * Method returns the {@link #_sleep} configuration value.
   * 
   * @return int millisecond sleep between server calls..
   */
  protected int getSleep() {
    return _sleep;
  }

  /**
   * String Method returns {@link #_port} configuration value.
   * 
   * @return int containing configured -port value.
   */
  protected int getPort() {
    return _port;
  }

  /**
   * Method returns {@link #_protocol} configuration value.
   * 
   * @return {@link String} containing -protocol value.
   */
  protected String getProtocol() {
    return _protocol;
  }

  /**
   * Method returns {@link #_serverPublicKeyFile} filename configuration value.
   * 
   * @return {@link String} containing configured -server-public-key value.
   */
  protected String getServerPublicKeyFile() {
    return _serverPublicKeyFile;
  }

  /**
   * Method returns {@link #_url} configuration value.
   * 
   * @return {@link String} containing configured -url value.
   */
  protected String getURL() {
    return _url;
  }

  /**
   * Method sets parameter field {@link _clientPrivateKeyFile} from
   * {@value ActiveMQClientParameterKeys#_KEY_CLIENT_PRIVATE_KEYFILE}.
   * 
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setClientPrivateKeyFile(Map<String, String> values) {

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_CLIENT_PRIVATE_KEYFILE)) {
      
      _clientPrivateKeyFile = values.get(ActiveMQClientParameterKeys._KEY_CLIENT_PRIVATE_KEYFILE);
      
      return true;
    }

    logMissingParameterError(ActiveMQClientParameterKeys._KEY_CLIENT_PRIVATE_KEYFILE);

    return false;
  }

  /**
   * Method sets parameter field {@link _clientPublicKeyFile} from
   * {@value ActiveMQClientParameterKeys#_KEY_CLIENT_PUBLIC_KEYFILE}.
   * 
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setClientPublicKeyFile(Map<String, String> values) {

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_CLIENT_PUBLIC_KEYFILE)) {
      
      _clientPublicKeyFile = values.get(ActiveMQClientParameterKeys._KEY_CLIENT_PUBLIC_KEYFILE);
      
      return true;
    }

    logMissingParameterError(ActiveMQClientParameterKeys._KEY_CLIENT_PUBLIC_KEYFILE);

    return false;
  }

  /**
   * Method sets parameter field {@link _credentials} from
   * {@value ActiveMQClientParameterKeys#_KEY_CREDENTIALS}.
   * 
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setCredentials(Map<String, String> values) {

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_CREDENTIALS)) {
      
      _credentials = values.get(ActiveMQClientParameterKeys._KEY_CREDENTIALS);
      
      return true;
    }

    logMissingParameterError(ActiveMQClientParameterKeys._KEY_CREDENTIALS);

    return false;
  }

  /**
   * Method sets parameter field {@link _debug} from
   * {@value ActiveMQClientParameterKeys#_KEY_DEBUG}.
   * 
   * @param values contains all loaded configuration parameter values._isValid
   * @return boolean indicating success or fail.
   */
  private boolean setDebug(Map<String, String> values) {

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_DEBUG)) {

      String value = values.get(ActiveMQClientParameterKeys._KEY_DEBUG);

      if (!(value == null || value.isBlank() || value.isEmpty())) {

        StringBuilder buffer = new StringBuilder();

        buffer.append("flag parameter -");
        buffer.append(ActiveMQClientParameterKeys._KEY_DEBUG);
        buffer.append(" should not have a value");

        _errors.add(buffer.toString());

        return false;
      }

      _debug = true;

      return true;
    
    } else {
      
      values.put(ActiveMQClientParameterKeys._KEY_DEBUG, "");

    }

    _debug = false;

    return true;
  }

  /**
   * Method sets parameter field {@link _unique} from
   * {@value ActiveMQClientParameterKeys#_KEY_UNIQUE}.
   * 
   * @param values contains all loaded configuration parameter values._isValid
   * @return boolean indicating success or fail.
   */
  private boolean setUnique(Map<String, String> values) {

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_UNIQUE)) {

      String value = values.get(ActiveMQClientParameterKeys._KEY_UNIQUE);

      if (!(value == null || value.isBlank() || value.isEmpty())) {

        StringBuilder buffer = new StringBuilder();

        buffer.append("flag parameter -");
        buffer.append(ActiveMQClientParameterKeys._KEY_UNIQUE);
        buffer.append(" should not have a value");

        _errors.add(buffer.toString());

        return false;
      }

      _unique = true;

      return true;
    
    } else {
      
      values.put(ActiveMQClientParameterKeys._KEY_UNIQUE, "");

    }

    _unique = false;

    return true;
  }

  /**
   * Method sets parameter field {@link _hostname} from
   * {@link ActiveMQClientParameterKeys#_KEY_HOSTNAME}
   * 
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setHostname(Map<String, String> values) {

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_HOSTNAME)) {

      _hostname = values.get(ActiveMQClientParameterKeys._KEY_HOSTNAME);

      return true;
    }

    logMissingParameterError(ActiveMQClientParameterKeys._KEY_HOSTNAME);

    return false;
  }

  /**
   * Method sets parameter field {@link _message} from
   * {@link ActiveMQClientParameterKeys#_KEY_MESSAGE}
   *
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setMessage(Map<String, String> values) {

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_MESSAGE)) {
      
      _message = values.get(ActiveMQClientParameterKeys._KEY_MESSAGE);
      
      return true;
    }

    logMissingParameterError(ActiveMQClientParameterKeys._KEY_MESSAGE);

    return false;
  }

  /**
   * Method sets parameter field {@link _channel} from
   * {@link ActiveMQClientParameterKeys#_KEY_CHANNEL}
   *
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setChannel(Map<String, String> values) {

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_CHANNEL)) {
      
      _channel = values.get(ActiveMQClientParameterKeys._KEY_CHANNEL);
      
      return true;
    }

    logMissingParameterError(ActiveMQClientParameterKeys._KEY_CHANNEL);

    return false;
  }

  /**
   * Method sets parameter field {@link _count} from
   * {@link ActiveMQClientParameterKeys#_KEY_COUNT}
   *
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setCount(Map<String, String> values) {

    int count = -1;

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_COUNT)) {

      String token = values.get(ActiveMQClientParameterKeys._KEY_COUNT).trim();

      try {

        if (!token.isBlank() || token.length() < 8) {
          count = Integer.parseInt(token);
        }

        if (count < 0) {
          count = 1;
        }

        if (count > 9999999) {
          count = 9999999;
        }

      } catch (NumberFormatException e) {

        _errors.add("-" + ActiveMQClientParameterKeys._KEY_COUNT + " is invalid number");

        return false;
      }

    } else {
      count = 1;

      values.put(ActiveMQClientParameterKeys._KEY_COUNT, "1");
    }

    _count = count;

    return true;
  }

  /**
   * Method sets parameter field {@link _sleep} from
   * {@link ActiveMQClientParameterKeys#_KEY_SLEEP}
   *
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setSleep(Map<String, String> values) {

    int sleep = -1;

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_SLEEP)) {

      String token = values.get(ActiveMQClientParameterKeys._KEY_SLEEP).trim();

      try {

        if (!token.isBlank() || token.length() < 8) {
          sleep = Integer.parseInt(token);
        }

        if (sleep < 0) {
          sleep = 0;
        }

        if (sleep > 9999999) {
          sleep = 9999999;
        }

      } catch (NumberFormatException e) {

        _errors.add("-" + ActiveMQClientParameterKeys._KEY_SLEEP + " is invalid number");

        return false;
      }

    } else {
      sleep = 0;

      values.put(ActiveMQClientParameterKeys._KEY_SLEEP, "0");
    }

    _sleep = sleep;

    return true;
  }

  /**
   * Method sets parameter field {@link _port} from
   * {@value ActiveMQClientParameterKeys#_KEY_PORT} Port value must be more than
   * 0. parameter. Port defaults to default port for protocol setting - either
   * '80' or '443'.
   * 
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setPort(Map<String, String> values) {

    int port = -1;

    if (_protocol.compareTo("http") == 0) {

      port = 80;

    } else if (_protocol.compareTo("https") == 0) {

      port = 443;

    } else {

      StringBuilder buffer = new StringBuilder();

      buffer.append("internal error ");
      buffer.append(ActiveMQClientParameterKeys._KEY_PROTOCOL);
      buffer.append(" must be set to 'http' or 'https' before ");
      buffer.append(ActiveMQClientParameterKeys._KEY_PORT);
      buffer.append(" can be set");

      _errors.add(buffer.toString());

      return false;
    }

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_PORT)) {
      try {

        port = Integer.parseInt(values.get(ActiveMQClientParameterKeys._KEY_PORT));

      } catch (NumberFormatException e) {

        _errors.add("-" + ActiveMQClientParameterKeys._KEY_PORT + " is invalid number");

        return false;
      }
    } else {
      values.put(ActiveMQClientParameterKeys._KEY_PORT, Integer.toString(port));
    }

    _port = port;

    if (_port < 0) {

      StringBuilder buffer = new StringBuilder();

      buffer.append("-");
      buffer.append(ActiveMQClientParameterKeys._KEY_PORT);
      buffer.append(" is not a valid port number - found ");
      buffer.append(_port);
      buffer.append(" from '");
      buffer.append(values.get(ActiveMQClientParameterKeys._KEY_PORT));
      buffer.append("' and '");
      buffer.append(_port);
      buffer.append("'");

      _errors.add(buffer.toString());

      return false;
    }

    return true;
  }

  /**
   * Method sets parameter field {@link _protocol} from
   * {@value ActiveMQClientParameterKeys#_KEY_PROTOCOL}. Can be 'http' or 'https'.
   * 
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setProtocol(Map<String, String> values) {

    String protocol = null;

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_PROTOCOL)) {
      protocol = values.get(ActiveMQClientParameterKeys._KEY_PROTOCOL);

      if (protocol.compareTo("http") != 0 && protocol.compareTo("https") != 0) {
        _errors.add("-" + ActiveMQClientParameterKeys._KEY_PROTOCOL + " must be value 'http' or 'https'");
        return false;
      }

    } else {
      protocol = "https";
      values.put(ActiveMQClientParameterKeys._KEY_PROTOCOL, protocol);
    }

    _protocol = protocol;

    return true;
  }

  /**
   * Method sets parameter field {@link _serverPublicKeyFile} from
   * {@value ActiveMQClientParameterKeys#_KEY_SERVER_PUBLIC_KEYFILE}.
   * 
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setServerPublicKeyFile(Map<String, String> values) {

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_SERVER_PUBLIC_KEYFILE)) {
      _serverPublicKeyFile = values.get(ActiveMQClientParameterKeys._KEY_SERVER_PUBLIC_KEYFILE);
      return true;
    }

    logMissingParameterError(ActiveMQClientParameterKeys._KEY_SERVER_PUBLIC_KEYFILE);

    return false;
  }

  /**
   * Method sets parameter field {@link _url} from
   * {@value ActiveMQClientParameterKeys#_KEY_URL}.
   * 
   * @param values contains all loaded configuration parameter values.
   * @return boolean indicating success or fail.
   */
  private boolean setURL(Map<String, String> values) {

    String url = null;

    if (values.containsKey(ActiveMQClientParameterKeys._KEY_URL)) {

      url = values.get(ActiveMQClientParameterKeys._KEY_URL);

    } else {

      url = "/activemq/server/logger/log";
      values.put(ActiveMQClientParameterKeys._KEY_URL, url);
    }

    _url = url;

    return true;
  }

  /**
   * Processing status.
   */
  private ActiveMQClientConfig.VALUES_STATUS _status = ActiveMQClientConfig.VALUES_STATUS.VALUES_STATUS_ERROR;

  /**
   * {@code List<String>} containing a list of errors encountered during parameter
   * processing.
   */
  protected List<String> _errors = new ArrayList<String>();

  /**
   * Configured location of the client's {@link java.security.PrivateKey}.
   */
  private String _clientPrivateKeyFile = "";

  /**
   * Configured location of the client's {@link java.security.PublicKey}.
   */
  private String _clientPublicKeyFile = "";

  /**
   * Configured location of the users credentials file.
   */
  private String _credentials = "";

  /**
   * Configured flag for additional debug output.
   */
  private boolean _debug = false;

  /**
   * Configured server name. Use Ip address (IPv4 only) or name.
   */
  private String _hostname = "";

  /**
   * Message to be sent to, and logged, by the remote service.
   */
  private String _message = "";
    
  /**
   * Configured unique parameter. Used to indicate whether message should be transformed before sending.
   */
  private boolean _unique = false;

  /**
   * Configured channel name.
   */
  private String _channel = "";

  /**
   * Configured server port.
   */
  private int _port = -1;

  /**
   * Configured message sleep.
   */
  private int _sleep = -1;

  /**
   * Configured number of message to send to server.
   */
  private int _count = -1;

  /**
   * Configured connection protocol. Must be either 'http' or 'https'.
   */
  private String _protocol = "";

  /**
   * Configured location of the server's {@link java.security.PublicKey}.
   */
  private String _serverPublicKeyFile = "";

  /**
   * Configured servlet Url prefix value.
   */
  private String _url = "";
  
}
