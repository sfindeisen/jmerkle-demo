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

public class JMerkleTreeDemo {

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
  }
}
