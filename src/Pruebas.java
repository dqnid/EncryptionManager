import java.security.KeyPair;

public class Pruebas {
    public static void main(String[] args) throws Exception {
        final String claro = "Hola mundo!";
        final String clave = "asdf";

        String cifrado = EncryptAlgorithms.blowFishEncrypt(claro,clave);

        System.out.println("El texto claro '"+ claro +"' se encripta con la clave '" + clave + "' como:\n" + cifrado);

        String descifrado = EncryptAlgorithms.blowFishDecrypt(cifrado,clave);
        System.out.println("\ny se desencripta como:"+ descifrado + "\n");
    }
}
