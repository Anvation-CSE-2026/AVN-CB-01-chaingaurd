package app;

import com.google.common.io.FileBackedOutputStream;

public class App {
  public static FileBackedOutputStream open() {
    return new FileBackedOutputStream(1024);
  }
}
