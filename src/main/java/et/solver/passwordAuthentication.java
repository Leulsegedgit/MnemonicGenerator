package et.solver;



import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;

//import com.profinch.abaybank.db.dbConn;

public final class passwordAuthentication
{
  private SecureRandom random;
  private int cost;
  private static String key = null;
  
  public passwordAuthentication()
  {
    this(16);
  }
  
  public passwordAuthentication(int cost)
  {
    iterations(cost);
    this.cost = cost;
    this.random = new SecureRandom();
  }
  
  private static int iterations(int cost)
  {
    if ((cost & 0xFFFFFFE1) != 0) {
      throw new IllegalArgumentException("cost: " + cost);
    }
    return 1 << cost;
  }
  
  public String hash(char[] password)
  {
    byte[] salt = new byte[16];
    this.random.nextBytes(salt);
    byte[] dk = pbkdf2(password, salt, 1 << this.cost);
    byte[] hash = new byte[salt.length + dk.length];
    System.arraycopy(salt, 0, hash, 0, salt.length);
    System.arraycopy(dk, 0, hash, salt.length, dk.length);
    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
    return enc.encodeToString(hash);
  }
  
  public boolean authenticate(char[] password, String token)
  {
    int iterations = iterations(this.cost);
    byte[] hash = Base64.getUrlDecoder().decode(token);
    byte[] salt = Arrays.copyOfRange(hash, 0, 16);
    byte[] check = pbkdf2(password, salt, iterations);
    int zero = 0;
    for (int idx = 0; idx < check.length; idx++) {
      zero |= hash[(salt.length + idx)] ^ check[idx];
    }
    return zero == 0;
  }
  
  private static byte[] pbkdf2(char[] password, byte[] salt, int iterations)
  {
    KeySpec spec = new PBEKeySpec(password, salt, iterations, 128);
    try
    {
      SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      return f.generateSecret(spec).getEncoded();
    }
    catch (NoSuchAlgorithmException ex)
    {
      throw new IllegalStateException("Missing algorithm: PBKDF2WithHmacSHA1", ex);
    }
    catch (InvalidKeySpecException ex)
    {
      throw new IllegalStateException("Invalid SecretKeyFactory", ex);
    }
  }
  
  @Deprecated
  public String hash(String password)
  {
    return hash(password.toCharArray());
  }
  
  @Deprecated
  public boolean authenticate(String password, String token)
  {
    return authenticate(password.toCharArray(), token);
  }
  
  private void getKey()
    
  {
    if (key == null)
    {
     key = "Profinch@Weg2017";
    }
  }
  
  public String encrypt(String text)
  {
    String ret = null;
    try
    {
      getKey();
      
      Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
      Cipher cipher = Cipher.getInstance("AES");
      
      cipher.init(1, aesKey);
      byte[] encrypted = cipher.doFinal(text.getBytes());
      byte[] encode = Base64.getEncoder().encode(encrypted);
      String pass = new String(encode);
      ret = pass;
    }
    catch (Exception e)
    {
     // log.error("Error during encrypt ", e);
    }
    return ret;
  }
  
}
