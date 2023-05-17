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
  void smallTree() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();

    MerkleTree mt = new MerkleTree(digest, 5);
    assertTrue(mt.isEmpty());
    assertEquals(0, mt.leafCount());

    mt.append(new byte[]{1,2,3,4,5,6,7});
    assertFalse(mt.isEmpty());
    assertEquals(2, mt.leafCount());
    assertEquals("549af97dc861cdd3f7c651be53f6458a68b87f6a924543ce572dc647d3e040d2", mt.rootHash());

    mt.append(new byte[]{8,9});
    assertFalse(mt.isEmpty());
    assertEquals(2, mt.leafCount());
    assertEquals("b0ed8285ccc6984845c1d579fe405d567ed7b14327f78555244b70d771ec98a8", mt.rootHash());

    mt.updateLeaf(0, new byte[]{20,21,22});
    assertFalse(mt.isEmpty());
    assertEquals(2, mt.leafCount());
    assertEquals("2eb4c74b7963c4dbcb322bda6cf681b2c8c655f8e7f4650654531b8af6b26330", mt.rootHash());
  }
}
