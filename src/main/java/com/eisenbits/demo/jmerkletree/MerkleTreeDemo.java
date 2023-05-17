package com.eisenbits.demo.jmerkletree;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Logger;
import java.util.random.RandomGenerator;
import java.util.stream.Collectors;

public class MerkleTreeDemo {

  private static MessageDigest makeDigest() throws NoSuchAlgorithmException {
    try {
      return MessageDigest.getInstance("SHA-128");
    } catch (NoSuchAlgorithmException e) {
      return MessageDigest.getInstance("SHA-256");
    }
  }

  public static void main(String[] args) throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    RandomGenerator rg = RandomGenerator.of("L64X128MixRandom");

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
