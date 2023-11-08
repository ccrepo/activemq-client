package cc.tools.activemq.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * This class implements file handling helper functionality to talk to an
 * ActiveMQServer instance.
 * 
 * @author cc
 * @version %I%, %G%
 * @since 0.1
 */
public class ActiveMQClientFile {

  /**
   * Constructor {@link ActiveMQClientFile}.
   */
  private ActiveMQClientFile() {
  }

  /**
   * Method loads file named in filename parameter. The contents of the file are
   * returned in a String object.
   * 
   * @param filename name of file to be loaded.
   * @param debug boolean indicating whether debug mode is on or not.
   * @return boolean indicating whether file contents were loaded into buffer
   *         parameter successfully.
   */
  static public String loadFile(String filename, boolean debug) {

    StringBuilder buffer = new StringBuilder();

    File file = new File(filename);

    if (!file.exists() || !file.canRead()) {
      
      _logger.error("filename '",
          filename,
          "' not accessible");

      return null;
    }

    FileInputStream inputStream = null;

    try {

      inputStream = new FileInputStream(file);

      if (file.length() < _MAXIMUM_ALLOWED_FILESIZE_BYTES) {

        byte bytes[] = new byte[(int) file.length()];

        inputStream.read(bytes);

        String data = new String(bytes, StandardCharsets.UTF_8);

        inputStream.close();

        buffer.append(data);

        return buffer.toString();
      }

      _logger.error("file is larger than maximum allowed size of ",
          _MAXIMUM_ALLOWED_FILESIZE_BYTES,
          " bytes - ",
          file.length());

    } catch (FileNotFoundException e) {

      _logger.exception(e);

    } catch (IOException e) {

      _logger.exception(e);

    }

    try {

      if (inputStream != null) {
        inputStream.close();
      }

    } catch (IOException e) {

      _logger.exception(e);

    }

    return null;
  }

  /**
   * Maximum allowed file size - '{@value _MAXIMUM_ALLOWED_FILESIZE_BYTES}' bytes.
   **/
  final public static int _MAXIMUM_ALLOWED_FILESIZE_BYTES = 10240;
  
  /**
   * Local logger reference for logging operations.
   */
  final private static ActiveMQClientLogger _logger = new ActiveMQClientLogger(ActiveMQClientFile.class.getName());
}
