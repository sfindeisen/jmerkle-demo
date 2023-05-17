import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Logger;
import java.util.random.RandomGenerator;
import java.util.stream.Collectors;

/**
 * ArrayList-based mutable Merkle tree implementation with bulk append and leaf update.
 */
class MerkleTree {

  /** Either a leaf (no children) or an internal node (1 or 2 children). */
  private static class Node {

    /**
     * Hash code of the corresponding DataBlock (if this is a leaf)
     * or of the children (if this is an internal node). If there
     * is only one child, it gets repeated.
     */
    byte[] hashval;
  }

  /** User data blocks, corresponding 1-1 to leaves in the tree. */
  private static class DataBlock {
    byte[] payload;

    void append(byte[] data, int offset, int length) {
      final int psz = psize();
      byte[] newdata = Arrays.copyOf(payload, psz + length);
      System.arraycopy(data, offset, newdata, psz, length);
      this.payload = newdata;
    }

    void append(byte[] data) {
      append(data, 0, data.length);
    }

    int psize() {
      return ((null == payload) ? 0 : payload.length);
    }
  }

  private static final Logger log = Logger.getLogger(MerkleTree.class.getName());
  private MessageDigest digest;

  /**
   * Maximum allowed number of data blocks (aka leaves). This limitation comes from
   * the internal use of java.util.ArrayList and its ability to index elements.
   *
   * TODO this could easily be fixed by substituting ArrayList with our own resizable array implementation
   */
  public static final int MaxBlocks = Integer.MAX_VALUE/2 - 5;
  private final int BlockSize;

  /**
   * A 1-based array containing all the leaves and internal nodes together.
   * The first slot is empty (null). See below for addressing.
   *
   * TODO fix doc
   */
  private ArrayList<Node> nodes = new ArrayList<>();

  /** A 0-based array containing all the data blocks, corresponding 1-1 to the leaves. */
  private ArrayList<DataBlock> datablocks = new ArrayList<>();

  /**
   * Pointer to the level of leaves in the nodes array, as power of 2, starting with 0.
   * The leaves are stored at: nodes[pow2[leafrowp]..pow2[leafrowp]+leafCount()-1].
   */
  private int leafrowp = 0;

  /** Powers of 2: pow2[k] == 2^k . */
  private static final int[] pow2;

  // initialize pow2 array
  static {
    pow2 = new int[1 + Integer.SIZE];
    int k = 1;
    for (int j=0; (j < pow2.length) && (1 <= k) && (k <= Integer.MAX_VALUE); ++j, k+=k)
      pow2[j] = k;
  }

  /** Finds the smallest exponent k such that: j <= 2^k. */
  private int findp2(int j) {
    // TODO binary search
    int i=0;
    for (; pow2[i] < j; ++i);
    return i;
  }

  /** nodes array access: parent node index */
  private int parind(int index1) {
    return index1 / 2;
  }
  /** nodes array access: left child node index */
  private int lci(int index1) {
    return 2 * index1;
  }
  /** nodes array access: right child node index */
  private int rci(int index1) {
    return 2 * index1 + 1;
  }
  ///** nodes array access: parent node */
  //private Node parent(int index) {
  //  return node(parind(index));
  //}

  /** Given a 1-based node index, returns the node. */
  private Node node(int index1) {
    return nodes.get(index1);
  }

  /** 0-based leaf index to 1-based node index */
  private int leaf2node(int index0) {
    return pow2[leafrowp] + index0;
  }

  /** Returns the total number of leaves (aka data blocks) stored in this tree. */
  public int leafCount() {
    return datablocks.size();
  }

  /** Returns the total number of nodes in this tree (not including the empty slot). */
  private int nodeCount() {
    return nodes.size() - 1;  // 1st slot is empty
  }

  public boolean isEmpty() {
    return datablocks.isEmpty();
  }

  /**
   * Resizes nodes array as needed to hold at least the given number of nodes.
   * Initializes the new nodes with null and appends them at the end.
   *
   * @param newNodeCount new number of nodes (not including the empty slot)
   */
  private void resizeNodes(int newNodeCount) {
    log.fine("newNodeCount=" + newNodeCount + ", nodes.size=" + nodes.size());
    if (nodes.size() < newNodeCount + 1) {
      nodes.ensureCapacity(newNodeCount + 1);
      nodes.addAll(Arrays.asList(Arrays.copyOf(new Node[0], newNodeCount + 1 - nodes.size())));
    }
  }

  /**
   * Resizes the nodes array and moves the existing nodes downwards (and leftwards)
   * in order to make space for the new part of the tree (possibly bigger).
   *
   * This leaves the nodes array in an inconsistent state (displaced root)!
   *
   * @param newLeafCnt new number of leaves
   */
  private void resize(int newLeafCnt) {
    final int newLeafRowP = findp2(newLeafCnt);                 // new bottom level
    final int newNodeCnt  = pow2[newLeafRowP] + newLeafCnt - 1; // new total number of nodes (not including the empty slot)
    final int hdiff = newLeafRowP - leafrowp;

    log.fine("leafCount=" + leafCount() + " leafrowp=" + leafrowp + " newNodeCnt=" + newNodeCnt +
             " newLeafCnt=" + newLeafCnt + " newLeafRowP=" + newLeafRowP + " hdiff=" + hdiff);
    resizeNodes(newNodeCnt);

    // iterate over the tree levels from bottom to top, moving them downwards (and leftwards)
    for (int level=leafrowp; 0 <= level; --level) {
      // move the entire level of nodes downwards (and leftwards)
      for (int i=0; (i < pow2[level]) && (null != nodes.get(pow2[level] + i)); ++i) {
        final int j = pow2[level] + i;
        final int k = pow2[level+hdiff] + i;
        log.fine("move " + j + " to " + k);
        nodes.set(k, nodes.get(j));
        nodes.set(j, null);
      }
    }
  }

  public byte[] rootHash() {
    if ((null == nodes) || (nodes.size() <= 1) || (null == nodes.get(1)))
      throw new IllegalStateException("Tree is empty!");
    // TODO fix reference leak
    return nodes.get(1).hashval;
  }

  private byte[] mkhash() {
    byte[] res = digest.digest();
    log.fine(Arrays.toString(res));
    return res;
  }

  private byte[] mkhash(byte[] data) {
    byte[] res = digest.digest(data);
    log.fine(Arrays.toString(res));
    return res;
  }

  /** Given a 0-based leaf index, updates its hash value. */
  private void recomputeLeafHash(int index0, boolean fixup) {
    final int index1 = leaf2node(index0);
    node(index1).hashval = mkhash(datablocks.get(index0).payload);
    if (fixup)
      fixUp(index1);
  }

  /**
   * Given a 1-based inner node index, updates its hash value.
   *
   * NOTE: this can be called in displaced root mode.
   */
  private void recomputeInnerNodeHash(int index1) {
    log.fine("" + index1);

    Node nd = node(index1);
    Node lc = node(lci(index1));
    Node rc = node(rci(index1));

    // This apparently does the right thing (hash of the concatenation)
    // TODO but mind the second preimage attack!
    digest.update(((null == lc) ? rc : lc).hashval);
    digest.update(((null == rc) ? lc : rc).hashval);
    nd.hashval = mkhash();
  }

  /** Given a 1-based node index, fixes the hash values up to the root, starting with the father. */
  private void fixUp(int index1) {
    for (int cnode = parind(index1); 1 <= cnode; cnode = parind(cnode))
      recomputeInnerNodeHash(cnode);
  }

  /**
   * Given a section of the tree row, updates all the hashes up to the tree root in breadth-first
   * fashion, starting with the fathers and creating the corresponding inner nodes as necessary.
   *
   * NOTE: this can be called in displaced root mode.
   *
   * @param fromIndex1 start index (inclusive)
   * @param   toIndex1   end index (exclusive)
   */
  private void fixUpMultiple(int fromIndex1, int toIndex1) {
    log.fine("fixUpMultiple: " + fromIndex1 + " .. " + toIndex1);
    if (toIndex1 <= fromIndex1)
      return;

    for (int i=fromIndex1; i < toIndex1; ++i) {
      final int pind1 = parind(i);
      Node pnode = nodes.get(pind1);

      if (null == pnode) {
        nodes.set(pind1, new Node());
        if ((i == (2 * pind1 + 1)) || (toIndex1 == i+1)) {
          // Either i is the right child or the last child (there is no right child)
          recomputeInnerNodeHash(pind1);
        }
      }
    }

    // ascend one level to the root
    // recursion: not a problem with the stack size, because log2 is small enough
    fixUpMultiple(parind(fromIndex1), parind(toIndex1));
  }

  /**
   * Updates the payload in the given node.
   *
   * @param index0 must be between 0 (inclusive) and leafCount() (exclusive)
   */
  public void updateLeaf(int index0, byte[] data) {
    if (BlockSize < data.length)
      throw new IllegalArgumentException("data length (" + data.length + ") is bigger than the allowed block size (" + BlockSize + ")");
    if ((index0 < 0) || (leafCount() <= index0))
      throw new IllegalArgumentException("Leaf index (" + index0 + ") out of bounds, must be between 0 (inclusive) and " + leafCount() + " (exclusive)");

    // update the payload
    datablocks.get(index0).payload = Arrays.copyOf(data, data.length);
    // update the hash and up to the root
    recomputeLeafHash(index0, true);
  }

  /**
   * Given a buffer of bytes, creates and appends the corresponding leaves and data blocks.
   *
   * NOTE: this can be called in displaced root mode.
   *
   * @param data
   * @param offset
   * @param leafptr where to start writing leaf nodes
   * @return the number of new data blocks equal to the number of new leaves
   */
  private void appendDataBlocks(byte[] data, int offset, int leafptr) {
    datablocks.ensureCapacity(1 + (data.length - offset) / BlockSize);

    for (int i=offset, k=0; i < data.length; i+=BlockSize, ++k) {
      DataBlock block = new DataBlock();
      block.payload   = Arrays.copyOfRange(data, i, Math.min(data.length, i+BlockSize));
      datablocks.add(block);

      Node leaf = new Node();
      leaf.hashval = mkhash(block.payload);
      nodes.set(leafptr + k, leaf);
    }
  }

  /** Modifies the tree by inserting the given data chunk at the end. */
  public void append(byte[] data) {
    if (0 == data.length)
      return;

    // number of existing nodes (not including the empty slot)
    final int oldNodes = nodeCount();

    // number of existing data blocks (equal to the number of leaves)
    final int oldBlocks = datablocks.size();

    // last data block
    final DataBlock lastBlock = datablocks.isEmpty() ? null : datablocks.get(datablocks.size()-1);

    // number of unused bytes in the last data block
    final int freeBytes = (null == lastBlock) ? 0 : (BlockSize - lastBlock.psize());

    // number of new data blocks to allocate
    final int newBlocks = (((data.length % BlockSize) <= freeBytes) ? 0 : 1)
                            + (data.length / BlockSize);

    // final number of data blocks (after append)
    final int allBlocks = oldBlocks + newBlocks;

    if (MaxBlocks < allBlocks)
      throw new IllegalArgumentException("Max blocks limit (" + MaxBlocks + ") exceeded!");

    // the new leaf row pointer
    final int newLeafRowPtr = findp2(allBlocks);

    if (leafrowp < newLeafRowPtr) {
      // leaves do not fit in the current level anymore and must be moved downwards
      resize(allBlocks);
      // The root node is now displaced!
      // But there is enough space in the bottom-most tree level to hold the new leaves.
      // New leaves start here
      final int leafPtr = pow2[newLeafRowPtr] + oldBlocks;
      // 1-based index of the last leaf node (if any)
      final int lastLeaf1 = leafPtr - 1;

      if (0 == freeBytes) {
        // Either no data or last block is full: start a new block
        appendDataBlocks(data, 0, leafPtr);
        fixUpMultiple(leafPtr, leafPtr + newBlocks);
      } else {
        // data.length > freeBytes (because of the new row)
        // Last block exists and is not full: fill it up first
        lastBlock.append(data, 0, freeBytes);
        // we cannot call recomputeLeafHash here because of the displaced root mode
        node(lastLeaf1).hashval = mkhash(lastBlock.payload);
        // create and append the remaining new leaves
        appendDataBlocks(data, freeBytes, leafPtr);
        // Fix the internal hashes, including the former last leaf path
        fixUpMultiple(lastLeaf1, lastLeaf1 + newBlocks + 1);
      }

      // update the leaf row pointer
      this.leafrowp = newLeafRowPtr;
    } else {
      // 0-based index of the last leaf (if any)
      final int lastLeaf0 = oldBlocks - 1;
      // 1-based index of the last leaf node (if any)
      final int lastLeaf1 = datablocks.isEmpty() ? 0 : leaf2node(lastLeaf0);

      // Just append the new leaves to the existing leaf row in the tree - no restructure needed.
      // Make some space in the nodes array...
      resizeNodes(oldNodes + newBlocks);
      // New leaves start here
      final int leafPtr = oldNodes + 1;

      if (0 == freeBytes) {
        // Either no data or last block is full: start a new block
        appendDataBlocks(data, 0, leafPtr);
        fixUpMultiple(leafPtr, leafPtr + newBlocks);
      } else {
        // Last block exists and is not full: fill it up first
        if (data.length <= freeBytes) {
          // Free space in the last block is big enough to hold the entire new data
          lastBlock.append(data);
          recomputeLeafHash(lastLeaf0, true);
        } else {
          // Fill up the last block
          lastBlock.append(data, 0, freeBytes);
          recomputeLeafHash(lastLeaf0, false);
          // create and append the remaining new leaves
          appendDataBlocks(data, freeBytes, leafPtr);
          // Fix the internal hashes, including the former last leaf path
          fixUpMultiple(lastLeaf1, lastLeaf1 + newBlocks + 1);
        }
      }
    }
  }

  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(datablocks.size() + " data blocks: [");
    sb.append(datablocks.stream().mapToInt(l -> l.psize()).mapToObj(String::valueOf).collect(Collectors.joining(",")));
    sb.append("]");
    if (! isEmpty())
      sb.append("; root hash: " + rootHash());
    return sb.toString();
  }

  public MerkleTree(MessageDigest digest, int blockSize) {
    if (blockSize < 3)
      throw new IllegalArgumentException("Maximal leaf data block size must be at least 3");

    this.digest = digest;
    this.BlockSize = blockSize;
    this.nodes.add(null); // 1st slot is empty

    log.info("hash function: " + digest.getAlgorithm());
    log.info("pow2: " + Arrays.toString(pow2));
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
