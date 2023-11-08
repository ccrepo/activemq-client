package cc.tools.activemq.client;

import static java.util.Map.entry;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * This class implements client functionality to talk to an ActiveMQServer
 * instance.
 * 
 * @author cc
 * @version %I%, %G%
 * @since 0.1
 */
public class ActiveMQClient {

  /**
   * Main method.
   * 
   * @param args program arguments.
   */
  public static void main(String[] args) {
    
    ActiveMQClient.logger().info("running pid " + ActiveMQClient.getPid());
    
    ActiveMQClientConfig config = new ActiveMQClientConfig(args);

    if (config.getIsHelp()) {
      config.doHelp();
      
      return;
    }

    if (!config.isValid()) {

      ActiveMQClient.logger().error("invalid parameters ",
          config.getErrors().size() +
          " errors");
      
      for (String error : config.getErrors()) {
        
        ActiveMQClient.logger().error("invalid parameters ",
            error);
      
      }

      return;
    }

    config.doDump();

    ActiveMQClient client = new ActiveMQClient(config);

    if (!client.isValid()) {
      
      ActiveMQClient.logger().error("client failed to initialise");
    
      return;
    
    }

    if (!client.sendMessagesToServer()) {
      
      ActiveMQClient.logger().error("send message to server failed");
      
      return;
    
    }

    ActiveMQClient.logger().info("fini");
  }

  /**
   * Constructor {@link ActiveMQClient}.
   * 
   * @param config {@link ActiveMQClientConfig} object containing program
   *               configuration values.
   */
  public ActiveMQClient(ActiveMQClientConfig config) {

    _config = config;

    if (_config == null || !_config.isValid()) {
      
      _logger.error("config not value");
      
      return;
    }

    _security = new ActiveMQClientSecurity(_config);

    if (!_security.isValid()) {
      
      _logger.error("security not value");
      
      return;
    }

    if (!setBaseUrl()) {
      
      _logger.error("could not set server's base URL");
      
      return;
    }

    _isValid = true;
  }

  /**
   * Method returns boolean indicating whether {@link ActiveMQClient} object is in
   * a valid state.
   * 
   * @return boolean where true indicates {@link ActiveMQClient} object is valid,
   *         false otherwise.
   */
  public boolean isValid() {
    
    return _isValid;
  
  }

  /**
   * Method sends configured message to the server.
   * 
   * @return boolean value set to true for success, false otherwise.
   */
  private boolean sendMessagesToServer() {

    int count = _config.getCount();

    _logger.info("sending messages ..");

    if (count == 0) {

      _logger.info("will send messages continuously every ", 
          Integer.toString(_config.getSleep()),
          " ms");

    } else {

      if (count == 1) {
        
        _logger.info("will send ",
            Integer.toString(count),
            " message");
        
      } else {
        
        _logger.info("will send ",
            Integer.toString(count),
            " message every ",
            Integer.toString(_config.getSleep()),
            "ms");
      }

    }

    long i = 0;
    
    if (i < count || count == 0) {
      
      while (true) {

        String number = Long.toString(i+1);

        StringBuilder prefix = new StringBuilder();

        prefix.append("[");
        prefix.append(number);
        prefix.append("]");


        _logger.info(prefix.toString(),
            " start message [",
            number,
            "]");

        if (!sendMessageToServer(number)) {

          _logger.error("send messages to server failed");

          return false;
        }

        if (count == 0) {

          _logger.info(prefix.toString(),
              " stop message [",
              number,
              "]");

        } else {

          _logger.info(prefix.toString(),
              " stop message [",
              number,
              "/",
              Integer.toString(count),
              "]");

        }

        _logger.info(prefix.toString(),
            " ok");

        i++;
        
        if (i < count || count == 0) {
        
          pause();
        
        } else {
          
          break;
          
        }
        
      }

    }

    return true;
  }

  /**
   * Method to sleep in production loop.
   */
  private void pause() {
  
    try {

      Thread.sleep(_config.getSleep());

    } catch (Exception e) {

      _logger.exception(e);

    }
    
  }
  
  /**
   * Method sends configured message to the server.
   * 
   * @param number message number.
   * @return boolean value set to true for success, false otherwise.
   */
  private boolean sendMessageToServer(String number) {

    StringBuilder buffer = new StringBuilder();

    Map<String, String> data = new HashMap<String, String>();

    String salt = ActiveMQClientSecurity.getRandom();

    try {

      if (!buildMessageData(data, salt, number)) {
        
        _logger.error("unable to build message data");

        return false;
      
      }

      int result = doPost(getPostUrl(), buffer, data, number);

      if (result < 0) {
      
        _logger.error("server call internal error - code ",
            Integer.toString(result));

        return false;
      
      }

      if (result != HttpURLConnection.HTTP_OK) {
        
        _logger.error("server call not ok - code ",
            Integer.toString(result));
        
        return false;
      
      }

      Map<String, String> response = _security.decodeData(buffer.toString());

      Map<String, StringBuilder> values = new HashMap<String, StringBuilder>();

      values
          .putAll(Map.ofEntries(
              entry(_HTTP_KEY_HEADER, new StringBuilder()), 
              entry(_HTTP_KEY_ID,     new StringBuilder()),
              entry(_HTTP_KEY_CODE,   new StringBuilder()), 
              entry(_HTTP_KEY_REMOTE, new StringBuilder())));

      if (!getFieldValuesFromRequest(response, values)) {
        
        _logger.error("fields not all found");

        return false;
      
      }

      String header  = values.get(_HTTP_KEY_HEADER).toString();
      String id      = values.get(_HTTP_KEY_ID).toString();
      String code    = values.get(_HTTP_KEY_CODE).toString();
      String remote  = values.get(_HTTP_KEY_REMOTE).toString();

      StringBuilder prefix = new StringBuilder();
      
      prefix.append("[");
      prefix.append(number);
      prefix.append("] [response] ");
      
      _logger.info(prefix.toString(),
          "header:  '",
          header,
          "'");
      
      _logger.info(prefix.toString(),
          "id:      '",
          id,
          "'");
  
      _logger.info(prefix.toString(),
          "code:    '",
          code,
          "'");
      
      _logger.info(prefix.toString(),
          "remote:  '",
          remote,
          "'");

      if (!code.equalsIgnoreCase("0")) {
      
        _logger.error("call failed with code '",
            code,
            "'");

        return false;
      
      }

    } catch (Exception e) {

      _logger.exception(e);

      return false;
    }

    return true;
  }

  /**
   * Method extracts list of values from the server response.
   * 
   * @param response data received from server..
   * @param values   request data is returned to client in this collection.
   * @return boolean true indicating success, false otherwise.
   */
  private boolean getFieldValuesFromRequest(Map<String, String> response, Map<String, StringBuilder> values) {

    boolean result = true;

    for (String key : values.keySet()) {

      try {

        String text = response.get(key);

        if (text == null || text.isBlank()) {
          
          _logger.error("key '",
              key,
              "' missing from reply");
          
          result = false;
        }

        values.get(key).append(text);

      } catch (Exception e) {

        _logger.exception(e);

        result = false;
      }

    }

    return result;
  }

  /**
   * Method to compose the outgoing message data.
   * 
   * @param data {@link java.util.Map} to return results.
   * @param salt random message salt. will be returned by server.
   * @param number message number. used for output prefix.
   * @return boolean to indicate success with true, false otherwise.
   */
  private boolean buildMessageData(Map<String, String> data, String salt, String number) {

    StringBuilder prefix = new StringBuilder();
    
    prefix.append("[");
    prefix.append(number);
    prefix.append("] [request] ");

    String header = _security.encryptServerData(salt);

    if (header == null || header.isBlank()) {
      
      _logger.error("could not get header data for message");
      
      return false;
    }

    data.put(_HTTP_KEY_HEADER, header);

    _logger.info(prefix.toString(),
        "header:  '",
        salt,
        "'");
    
    String user = _security.getUser();

    if (user == null || user.isBlank()) {
      
      _logger.error("could not get user data for message");
      
      return false;
    }

    data.put(_HTTP_KEY_USER, user);

    _logger.info(prefix.toString(),
        "user:     ********");
    
    String password = _security.getPassword();

    if (password == null || password.isBlank()) {
      
      _logger.error("could not get password data for message");
      
      return false;
    }

    data.put(_HTTP_KEY_PASSWORD, password);

    _logger.info(prefix.toString(),
        "password: ********");
        
    String channel = _config.getChannel();

    if (channel == null || channel.isBlank()) {
      
      _logger.error("could not get channel data for message");
      
      return false;
    }

    if (!channel.matches(_pattern)) {
      
      _logger.error("could not get channel data for message");
      
      return false;
    }

    data.put(_HTTP_KEY_CHANNEL, _security.encryptServerData(channel));

    _logger.info(prefix.toString(),
        "channel:  '",
        channel,
        "'");
    
    String message = _config.getMessage();

    if (message == null || 
        message.isBlank()) {
      
      _logger.error("could not get message data for message");
      
      return false;
    }

    if (_config.getUnique()) {
    
      message = number + 
        "/" + 
        message + 
        "/" + 
        new Date().toString();

    }

    _logger.info(prefix.toString(),
        "message:  '",
        message,
        "'");
        
    data.put(_HTTP_KEY_MESSAGE, _security.encryptServerData(message));

    _logger.info(prefix.toString(),
        "pid:      '",
        _pid,
        "'");
    
    data.put(_HTTP_KEY_PID, _security.encryptServerData(_pid));
    
    return true;
  }

  /**
   * Method returns Post Url for configuration..
   * 
   * @return {@link String} containing 'Post' endpoint Url.
   */
  private String getPostUrl() {

    StringBuilder buffer = new StringBuilder();

    buffer.append(_baseURL);
    
    buffer.append("/post");

    return buffer.toString();
  }

  /**
   * Method sets server's base Url value.
   * 
   * @return boolean true if success, false otherwise.
   */
  private boolean setBaseUrl() {

    StringBuilder buffer = new StringBuilder();

    buffer.append(_config.getProtocol());
    buffer.append("://");
    buffer.append(_config.getHostname());
    buffer.append(":");
    buffer.append(Integer.toString(_config.getPort()));
    buffer.append(_config.getURL());

    this._baseURL = buffer.toString();

    return true;
  }

  /**
   * Method performs http put call to server and returns status of a http put call
   * and server response data in responseBuffer parameter.
   * 
   * @param url    server url to call.
   * @param buffer buffer to return server response to caller.
   * @param data   name/value pairs of data that should be sent to server.
   * @param number message number. used for output.
   * @throws Exception based on errors encountered formatting/encoding data and.
   *                   communicating with server.
   * @return int containing returned http status.
   *         {@link java.net.HttpURLConnection} (HTTP_OK
   *         {@value java.net.HttpURLConnection#HTTP_OK}, HTTP_BAD_REQUEST
   *         {@value java.net.HttpURLConnection#HTTP_BAD_REQUEST} etc). server
   *         response is returned in parameter buffer
   */
  private int doPost(String url, StringBuilder buffer, Map<String, String> data, String number) throws Exception {

    _logger.info("[",
        number,
        "] [sending] url: ",
        url);

    HttpRequest.BodyPublisher encoded = _security.encodeData(data);

    if (encoded == null) {
      return -1;
    }

    HttpRequest request = HttpRequest.newBuilder().POST(encoded).uri(URI.create(url))
        .setHeader("User-Agent", this.getClass().getSimpleName() + "command line program")
        .header("Content-Type", "application/x-www-form-urlencoded").build();

    HttpResponse<String> httpResponse = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    buffer.append(httpResponse.body());

    return httpResponse.statusCode();
  }

  /**
   * Method returns reference to logger object.
   * @return ActiveMQClientLogger logger.
   */
  static public ActiveMQClientLogger logger() {
    return _logger;
  }
  
  /**
   * Method to get process PID as a string.
   * @return String containing process pid.
   */
  static public String getPid() {
    return _pid;  
  }
  
  /**
   * Configuration object containing parameter settings.
   */
  private ActiveMQClientConfig _config = null;

  /**
   * Security object for key based operations.
   */
  private ActiveMQClientSecurity _security = null;

  /**
   * Sever's base IRI from configuration
   */

  private String _baseURL = null;

  /**
   * Boolean indicating whether this {@link ActiveMQClient} object is in a valid
   * state.
   */
  private boolean _isValid = false;

  /**
   * HTTP message key '{@value _HTTP_KEY_PASSWORD}'.
   */
  final public static String _HTTP_KEY_PASSWORD = "password";

  /**
   * HTTP message key '{@value _HTTP_KEY_USER}'.
   */
  final public static String _HTTP_KEY_USER = "user";

  /**
   * HTTP message key '{@value _HTTP_KEY_HEADER}'.
   */
  final public static String _HTTP_KEY_HEADER = "header";

  /**
   * HTTP message key '{@value _HTTP_KEY_MESSAGE}'.
   */
  final public static String _HTTP_KEY_MESSAGE = "message";

  /**
   * HTTP message key '{@value _HTTP_KEY_CHANNEL}'.
   */
  final public static String _HTTP_KEY_CHANNEL = "channel";
    
  /**
   * HTTP message key '{@value _HTTP_KEY_PID}'.
   */
  final public static String _HTTP_KEY_PID = "pid";
    
  /**
   * HTTP timeout '{@value _HTTP_TIMEOUT_SECONDS}' seconds.
   **/
  final public static int _HTTP_TIMEOUT_SECONDS = 10;

  /**
   * HTTP message key '{@value _HTTP_KEY_ID}'.
   */
  final public static String _HTTP_KEY_ID = "id";

  /**
   * HTTP message key '{@value _HTTP_KEY_CODE}'.
   */
  final public static String _HTTP_KEY_CODE = "code";

  /**
   * HTTP message key '{@value _HTTP_KEY_REMOTE}'.
   */
  final public static String _HTTP_KEY_REMOTE = "remote";

  /**
   * {@link java.net.http.HttpClient} object for calls to server.
   */
  final private HttpClient _httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2)
      .connectTimeout(Duration.ofSeconds(_HTTP_TIMEOUT_SECONDS)).build();
  
  /**
   * Local logger reference for logging operations.
   */
  final private static ActiveMQClientLogger _logger = new ActiveMQClientLogger(ActiveMQClient.class.getName());
  
  /**
   * Pattern for matching channel names.
   */
  private static final String _pattern = "^[/a-zA-Z0-9\\.]+$";

  /**
   * Stores PID of current process.
   */
  private static final String _pid = Long.toString(ProcessHandle.current().pid());
}
