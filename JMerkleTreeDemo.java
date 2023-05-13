import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;
import java.util.random.RandomGenerator;

class MerkleTree {

  private static class Node {
    private static final Logger log = Logger.getLogger(Node.class.getName());

    byte[] payload;
    Node lc;
    Node rc;
  }

  private static final Logger log = Logger.getLogger(MerkleTree.class.getName());
  private MessageDigest digest;
  private RandomGenerator rg;
  private Node root;

  public MerkleTree(MessageDigest digest, RandomGenerator rg) {
    this.digest = digest;
    this.rg = rg;

    log.info("hash function: " + digest.getAlgorithm());
    log.info("random number generator: " + rg.toString());
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
    MerkleTree mt = new MerkleTree(digest, rg);
  }
}
