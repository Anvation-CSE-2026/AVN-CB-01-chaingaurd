package app;

import com.google.common.io.Files;

public class App {
  public static Object dir() throws Exception {
    return Files.createTempDir();
  }
}
