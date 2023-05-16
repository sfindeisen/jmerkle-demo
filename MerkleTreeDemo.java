import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Logger;
import java.util.random.RandomGenerator;
import java.util.stream.Collectors;

class MerkleTree {

  private static class Node {
    private static final Logger log = Logger.getLogger(Node.class.getName());

    /** This is either raw data (as in a leaf) or hash (as in an internal node). */
    byte[] payload;
    Node parent;
    Node lc;
    Node rc;

    int psize() {
      return ((null == payload) ? 0 : payload.length);
    }
  }

  private static final Logger log = Logger.getLogger(MerkleTree.class.getName());
  private MessageDigest digest;
  private Node root;
  private final int BlockSize;
  private ArrayList<Node> leaves = new ArrayList<>();

  // Tainted leaves: from taintStart (inclusive) to taintEnd (exclusive).
  private int taintStart = -1;
  private int taintEnd   = -1;

  public byte[] rootHash() {
    if (null == root)
      throw new IllegalStateException("Tree is empty!");
    return root.payload;
  }

  private byte[] mkhash() {
    byte[] res = digest.digest();
    log.fine("mkhash: " + res);
    return res;
  }

  private byte[] mkhash(byte[] data) {
    byte[] res = digest.digest(data);
    log.fine("mkhash: " + res);
    return res;
  }

  private boolean isModified() {
    return (0 <= taintStart) && (taintStart < taintEnd);
  }

  private void recompute() {
    if (isModified()) {
      // TODO
      taintStart = -1;
      taintEnd   = -1;
    }
  }

  private void recompute_hash(Node node) {
    // This apparently does the right thing (hash of the concatenation)
    digest.update(((null == node.lc) ? node.rc : node.lc).payload);
    digest.update(((null == node.rc) ? node.lc : node.rc).payload);
    node.payload = mkhash();
  }

  private void fixup(Node leaf) {
    leaf.parent.payload = mkhash(leaf.payload);
    Node prev = leaf.parent;
    Node node = leaf.parent.parent;

    for (; null != node; prev=node, node=node.parent) {
      recompute_hash(node);
    }
  }

  public void updateLeaf(int index, byte[] data) {
    if (BlockSize < data.length)
      throw new IllegalArgumentException("data length (" + data.length + ") is bigger than the block size (" + BlockSize + ")");
    if ((index < 0) || (leaves.size() <= index))
      throw new IllegalArgumentException("Invalid leaf index (" + index + "), must be between 0 and " + leaves.size() + " (exclusive)");
    Node leaf = leaves.get(index);
    leaf.payload = Arrays.copyOf(data, data.length);
    fixup(leaf);
  }

  private void append(byte[] data, int offset) {
    for (int i=offset; i < data.length; i += BlockSize) {
      Node leaf = new Node();
      leaf.payload = Arrays.copyOfRange(data, i, Math.min(data.length, i+BlockSize));
      leaves.add(leaf);
    }
  }

  /** Modifies the tree by inserting the given data chunk at the end. */
  public void append(byte[] data) {
    if (0 == data.length)
      return;

    if (leaves.isEmpty() || (BlockSize == leaves.get(leaves.size()-1).psize())) {
      // Either no data or last block is full: start a new block
      taintStart = leaves.size();
      append(data, 0);
    } else {
      // Last block is not full: fill it up first
      Node lastLeaf = leaves.get(leaves.size()-1);
      final int llsz = lastLeaf.psize();

      if (llsz + data.length <= BlockSize) {
        // Free space in the last block is enough to contain the entire new data
        lastLeaf.payload = Arrays.copyOf(lastLeaf.payload, llsz + data.length);
        System.arraycopy(data, 0, lastLeaf.payload, llsz, data.length);
        taintStart = leaves.size() - 1;
      } else {
        // Fill up the last block ...
        final int offset = BlockSize - llsz;
        lastLeaf.payload = Arrays.copyOf(lastLeaf.payload, BlockSize);
        System.arraycopy(data, 0, lastLeaf.payload, llsz, offset);
        taintStart = leaves.size() - 1;
        // ... then create and append new leaves
        append(data, offset);
      }
    }

    taintEnd = leaves.size();
  }

  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("MerkleTree of " + leaves.size() + " leaves: [");
    sb.append(leaves.stream().mapToInt(l -> l.psize()).mapToObj(String::valueOf).collect(Collectors.joining(",")));
    sb.append("]");
    if (null != root)
      sb.append("; root hash: " + rootHash());
    return sb.toString();
  }

  public MerkleTree(MessageDigest digest, int blockSize) {
    if (blockSize < 3)
      throw new IllegalArgumentException("Maximal leaf data block size must be at least 3");

    this.digest = digest;
    this.BlockSize = blockSize;

    log.info("hash function: " + digest.getAlgorithm());
  }
}

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
    mt.append(new byte[]{1,2,3,4,5,6,7});
    System.out.println(mt.toString());
    mt.append(new byte[]{8,9});
    System.out.println(mt.toString());
    mt.updateLeaf(0, new byte[]{20,21,22});
    System.out.println(mt.toString());
  }
}
