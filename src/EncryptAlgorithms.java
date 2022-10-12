import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class EncryptAlgorithms {
    /**
     * Algoritmo de resumen
     **/
    public static byte[] SHA256(String input)
    {
        MessageDigest dig = null;
        try {
            dig = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return dig.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] MD5(String input)
    {
        MessageDigest dig = null;
        try {
            dig = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return dig.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Cifrado de clave pública
     * RSA (claves de mínimo 1024)
     **/
    public static KeyPair RSAGenKeys(int size)
    {
        KeyPairGenerator generador = null;
        try {
            generador = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        generador.initialize(size);
        return generador.generateKeyPair();
    }

    public static byte[] RSAEncripta(PublicKey clave, String mensaje)
    {
        byte[] claro = mensaje.getBytes(StandardCharsets.UTF_8);
        Cipher encriptador = null;
        try {
            encriptador = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        try {
            encriptador.init(Cipher.ENCRYPT_MODE, clave);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        try {
            return encriptador.doFinal(claro);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String RSADesencripta(PrivateKey clave, byte[] cifrado)
    {
        Cipher desencriptador = null;
        try {
            desencriptador = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        try {
            desencriptador.init(Cipher.DECRYPT_MODE, clave);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        byte[] desencriptado = new byte[0];
        try {
            desencriptado = desencriptador.doFinal(cifrado);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
        return new String(desencriptado);
    }

    public static String byteToString(byte[] bytes) {
        byte[] encoded = Base64.getEncoder().encode(bytes);
        return new String(encoded, StandardCharsets.UTF_8);
    }

    /**
     * Cifrado de clave privada
     * Blowfish
     **/
    public static byte[] BlowFishEncrypt(String str, String key){
        byte[] encrypted;
        byte[] KeyData = key.getBytes();
        SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("Blowfish");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, KS);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
        try {
            encrypted = cipher.doFinal(str.getBytes(StandardCharsets.UTF_8));
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
        return encrypted;
    }

    public static byte[] BlowFishDecrypt(byte[] encrypted, String key){
        byte[] decrypted;
        byte[] KeyData = key.getBytes();
        SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("Blowfish");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, KS);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
        try {
            decrypted = cipher.doFinal(encrypted);
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
        return decrypted;
    }
}
