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
  void tree2append20() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);
    assertTrue(mt.isEmpty());
    assertEquals(0, mt.leafCount());

    mt.append(new byte[]{8,9});
    assertFalse(mt.isEmpty());
    assertEquals(1, mt.leafCount());
    assertEquals("69ef868802cda4ddd19e4e83e5dbd926b39610b1d391350fd85f3f2df09a5835", mt.rootHash());

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20});
    assertFalse(mt.isEmpty());
    assertEquals(8, mt.leafCount());
    assertEquals("8aad9d91474df0650102498c2fbd0c3b296976fc755bf973390b684ee75e0ee5", mt.rootHash());
  }

  @Test
  void tree3append20() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);
    assertTrue(mt.isEmpty());
    assertEquals(0, mt.leafCount());

    mt.append(new byte[]{7,8,9});
    assertFalse(mt.isEmpty());
    assertEquals(1, mt.leafCount());
    assertEquals("fb31b1fe1703150927333b4e3ba18d9b54c21714c20505879f6428622fdbea88", mt.rootHash());

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20});
    assertFalse(mt.isEmpty());
    assertEquals(8, mt.leafCount());
    assertEquals("d42cc7ecfcfe92d06a7277f3105a4cbd280cd0f57eb6f214b47f11f6cc5af700", mt.rootHash());
  }

  @Test
  void tree4append20() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);
    assertTrue(mt.isEmpty());
    assertEquals(0, mt.leafCount());

    mt.append(new byte[]{6,7,8,9});
    assertFalse(mt.isEmpty());
    assertEquals(2, mt.leafCount());
    assertEquals("27cfac2e92d26e478b0b66ed2d7b2964abd8730d3d7873412593d756913862aa", mt.rootHash());

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20});
    assertFalse(mt.isEmpty());
    assertEquals(8, mt.leafCount());
    assertEquals("9188b891f91cad5c9282b8821e924e0aa8d1b7ffe41a934eb346bc5e5044defa", mt.rootHash());
  }

  @Test
  void tree5append20() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);
    assertTrue(mt.isEmpty());
    assertEquals(0, mt.leafCount());

    mt.append(new byte[]{5,6,7,8,9});
    assertFalse(mt.isEmpty());
    assertEquals(2, mt.leafCount());
    assertEquals("f2d2af1327e900cb78d94a7af142b83fe24d7fba6553040170a624a1dbf249eb", mt.rootHash());

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20});
    assertFalse(mt.isEmpty());
    assertEquals(9, mt.leafCount());
    assertEquals("19db03ef42128e32a312d5dcd11a3ae722e3c98c109e306bfdcf8f7d69975619", mt.rootHash());
  }

  @Test
  void tree20append2() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20});
    assertEquals(7, mt.leafCount());
    assertEquals("257430c9dc285855d7c5297172e40c7bfdcde80f17a6e65efa5630078cd50969", mt.rootHash());

    mt.append(new byte[]{8,9});
    assertEquals(8, mt.leafCount());
    assertEquals("43697f42a670936e3ed6c1f8cd83869c3e0640243384b49574bea24d2575fb4a", mt.rootHash());
  }

  @Test
  void tree20append3() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20});
    assertEquals(7, mt.leafCount());
    assertEquals("257430c9dc285855d7c5297172e40c7bfdcde80f17a6e65efa5630078cd50969", mt.rootHash());

    mt.append(new byte[]{8,9,10});
    assertEquals(8, mt.leafCount());
    assertEquals("accee94654c6435845a91f37a6a2f828fe5b35547df126d0b094d964f5d85da4", mt.rootHash());
  }

  @Test
  void tree18append6() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18});
    assertEquals(6, mt.leafCount());
    assertEquals("8632a4507b3961a32cf33e3193e9289389f0260720028462645094880a1d0489", mt.rootHash());

    mt.append(new byte[]{19,20,8,9,10,11});
    assertEquals(8, mt.leafCount());
    assertEquals("4b5f7917b964575ef171412abee3a1894e449947ce80d8dbc36f8c9d60573eff", mt.rootHash());
  }

  @Test
  void tree19append5() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19});
    assertEquals(7, mt.leafCount());
    assertEquals("bca6f6a6e7bfe4c712188527735fc18f2858fd4520c0bc673632dba47639f844", mt.rootHash());

    mt.append(new byte[]{20,8,9,10,11});
    assertEquals(8, mt.leafCount());
    assertEquals("4b5f7917b964575ef171412abee3a1894e449947ce80d8dbc36f8c9d60573eff", mt.rootHash());
  }

  @Test
  void tree20append4() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20});
    assertEquals(7, mt.leafCount());
    assertEquals("257430c9dc285855d7c5297172e40c7bfdcde80f17a6e65efa5630078cd50969", mt.rootHash());

    mt.append(new byte[]{8,9,10,11});
    assertEquals(8, mt.leafCount());
    assertEquals("4b5f7917b964575ef171412abee3a1894e449947ce80d8dbc36f8c9d60573eff", mt.rootHash());
  }

  @Test
  void tree20append5() throws NoSuchAlgorithmException {
    MessageDigest digest = makeDigest();
    MerkleTree mt = new MerkleTree(digest, 3);

    mt.append(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20});
    assertEquals(7, mt.leafCount());
    assertEquals("257430c9dc285855d7c5297172e40c7bfdcde80f17a6e65efa5630078cd50969", mt.rootHash());

    mt.append(new byte[]{8,9,10,11,12});
    assertEquals(9, mt.leafCount());
    assertEquals("f7ededea0ee66f59fb7a807333c5895c15074e602428512821029847dda1b51d", mt.rootHash());
  }
}
