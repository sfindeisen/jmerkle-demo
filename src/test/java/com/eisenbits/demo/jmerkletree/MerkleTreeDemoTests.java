package com.eisenbits.demo.jmerkletree;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class MerkleTreeDemoTests {

  private static MessageDigest makeDigest() throws NoSuchAlgorithmException {
    return MessageDigest.getInstance("SHA-256");
  }

  @Test
  void emptyTree() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 5);
    assertTrue(mt.isEmpty());
    assertEquals(0, mt.leafCount());
  }

  @Test
  void smallTree() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();

    MerkleTree mt = new MerkleTree(digest, 5);
    assertTrue(mt.isEmpty());
    assertEquals(0, mt.leafCount());

    mt.append(new byte[]{1,2,3,4,5,6,7});
    assertFalse(mt.isEmpty());
    assertEquals(2, mt.leafCount());
    assertEquals("f16a90becd1fb59e19e7294e2fc0f549bba07bec57932ab482b2e88c56d84964", mt.rootHash());

    mt.append(new byte[]{8,9});
    assertFalse(mt.isEmpty());
    assertEquals(2, mt.leafCount());
    assertEquals("23fe91c8398c7a228f2c35a0b9021257f38907d3932ff3e808c61c0c836976b7", mt.rootHash());

    mt.updateLeaf(0, new byte[]{20,21,22});
    assertFalse(mt.isEmpty());
    assertEquals(2, mt.leafCount());
    assertEquals("ee6cd779efc6f2b256af3a649d7ec2fa3991cd287cdba9cf119f44c9bf83f289", mt.rootHash());
  }

  @Test
  void tree20() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20});
    assertEquals(7, mt.leafCount());
    assertEquals("257430c9dc285855d7c5297172e40c7bfdcde80f17a6e65efa5630078cd50969", mt.rootHash());

    mt.append(new byte[]{8,9});
    assertEquals(8, mt.leafCount());
    assertEquals("43697f42a670936e3ed6c1f8cd83869c3e0640243384b49574bea24d2575fb4a", mt.rootHash());
  }
}
