package com.eisenbits.demo.jmerkletree;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;
import java.util.logging.LogManager;

public class MerkleTreeDemo {

  private static final Logger log = Logger.getLogger(MerkleTreeDemo.class.getName());

  /**
   * Configures java.util.logging using the logging.properties file.
   *
   * Based on: https://stackoverflow.com/a/14944846 .
   */
  private static void configureLogging() throws IOException {
    final String logFile = System.getProperty("java.util.logging.config.file");
    if (null == logFile) {
      log.info("try to configure logging using logging.properties file from the classpath");
      LogManager.getLogManager().readConfiguration(MerkleTreeDemo.class.getClassLoader().getResourceAsStream("logging.properties"));
    } else {
      log.info("logging config file: " + logFile);
    }
  }

  private static MessageDigest makeDigest() throws NoSuchAlgorithmException {
    try {
      return MessageDigest.getInstance("SHA-128");
    } catch (NoSuchAlgorithmException e) {
      return MessageDigest.getInstance("SHA-256");
    }
  }

  public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
    configureLogging();
    MessageDigest digest = makeDigest();

    MerkleTree mt = new MerkleTree(digest, 5);
    System.out.println(mt.toString());

    mt.append(new byte[]{1,2,3,4,5,6,7});
    System.out.println(mt.toString());

    mt.append(new byte[]{8,9});
    System.out.println(mt.toString());

    mt.updateLeaf(0, new byte[]{20,21,22});
    System.out.println(mt.toString());
  }
}
