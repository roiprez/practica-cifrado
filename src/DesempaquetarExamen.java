import Resources.Paquete;
import Resources.PaqueteDAO;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DesempaquetarExamen {
    /* args[0] = "Alumno.paquete";
    args[1] = "ExamenDescifrado.txt";
    args [2] = "EntSellado.publica";
    args [3] = "Alumno.publica";
    args [4] = "Profesor.privada";*/

    public static void main(String[] args) throws Exception {

        // Comprobar argumentos
        if (args.length != 5) {
            System.out.println("Numero de Argumentos incorrecto");
            System.exit(1);
        }

        Security.addProvider(new BouncyCastleProvider());

        PublicKey entSelladoPublica = getPublicKeyFromFile(args[2]);
        PublicKey alumnoPublica = getPublicKeyFromFile(args[3]);
        PrivateKey profesorPrivateKey = getPrivateKeyFromFile(args[4]);

        // Leer Alumno.paquete de la entidad de sellado
        Paquete paqueteSellado = desempaquetador(args[0]);

        // Comprobamos que el sello de tiempo está correctamente puesto
        if (comprobarSello(paqueteSellado, entSelladoPublica)) {
            System.out.println("El sello es correcto y no ha sufrido modificaciones");
        } else {
            System.out.println("\nEl sello no se ha hecho en la hora indicada por la Entidad de Sellado");
            System.exit(1);
        }

        // Desciframos el contenido del Examen
        descifrarExamen(paqueteSellado, profesorPrivateKey, args[1]);

        //Comprobamos que el contenido del examen pertenece realmente al Alumno
        byte[] datosFirma = paqueteSellado.getBloque("Firma").getContenido();
        byte[] firmaHash = desencriptarResumen(datosFirma, alumnoPublica);
        byte[] hashingExamen = funcionHashing(args[1]);

        if (MessageDigest.isEqual(hashingExamen, firmaHash)) {
            System.out.println("El examen ha sido realizado por el alumno");
        } else {
            System.out.println("El alumno no es el autor del examen");
        }

    }

    private static Paquete desempaquetador(String filename) {
        return PaqueteDAO.leerPaquete(filename);
    }

    private static Boolean comprobarSello(Paquete paquete, PublicKey entSelladoPublica) throws Exception {

        byte[] selloCifrado = paquete.getBloque("Sello").getContenido();
        byte[] timeStamp = paquete.getBloque("TimeStamp").getContenido();
        byte[] datosFirma = paquete.getBloque("Firma").getContenido();
        byte[] hashFirma = funcionHashFirma(datosFirma, timeStamp);
        byte[] selloDescifrado = descifrarHashFirma(selloCifrado, entSelladoPublica);
        String timeStampStr = new String(timeStamp);
        System.out.println("Fecha del sello: " + timeStampStr);

        return MessageDigest.isEqual(selloDescifrado, hashFirma);
    }

    private static void descifrarExamen(Paquete paquete, PrivateKey clavePrivProf, String path) throws Exception {
        byte[] examenAlumnoCifrado = paquete.getBloque("Examen").getContenido();
        byte[] claveSimetrica = paquete.getBloque("Clave").getContenido();

        byte[] claveSimetricaDescifrada = descifrarClaveSecreta(claveSimetrica, clavePrivProf);

        SecretKey clave = new SecretKeySpec(claveSimetricaDescifrada, 0, claveSimetricaDescifrada.length, "DES");
        descifrarSimetrico(examenAlumnoCifrado, clave, path);
    }

    private static byte[] funcionHashing(String file) throws Exception {

        MessageDigest messageDigest = MessageDigest.getInstance("MD5");

        /* Leemos el fichero por Kylobytes y se los vamos pasando a la funcion  hashing */
        byte[] buffer = new byte[1000];

        FileInputStream in = new FileInputStream(file);
        int leidos = in.read(buffer, 0, 1000);

        while (leidos != -1) {
            messageDigest.update(buffer, 0, leidos);
            leidos = in.read(buffer, 0, 1000);
        }

        in.close();

        return messageDigest.digest(); // Completar el resumen

    }

    private static byte[] desencriptarResumen(byte[] datosFirma, PublicKey alumnoPublica) throws Exception {

        Cipher cifrador = Cipher.getInstance("RSA", "BC");

        cifrador.init(Cipher.DECRYPT_MODE, alumnoPublica);

        return cifrador.doFinal(datosFirma);

    }

    private static byte[] descifrarHashFirma(byte[] hashFirma, PublicKey entSelladoPublica) throws Exception {

        Cipher cifrador = Cipher.getInstance("RSA", "BC");

        cifrador.init(Cipher.DECRYPT_MODE, entSelladoPublica);

        return cifrador.doFinal(hashFirma);

    }

    private static byte[] funcionHashFirma(byte[] datosFirma, byte[] TIMESTAMP) throws Exception {
        /* Crear funcion resumen */
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");

        messageDigest.update(datosFirma); // Hacer el hash de los datos de firma
        messageDigest.update(TIMESTAMP); // A�adimos el hash de timestamp

        return messageDigest.digest();

    }

    private static byte[] descifrarClaveSecreta(byte[] clave, PrivateKey ProfesorPrivateKey) throws Exception {

        Cipher cifrador = Cipher.getInstance("RSA", "BC");

        cifrador.init(Cipher.DECRYPT_MODE, ProfesorPrivateKey);  // Descifra con la clave privada

        return cifrador.doFinal(clave);

    }

    private static void descifrarSimetrico(byte[] stringCifrado, SecretKey clave, String path) throws Exception {

        /* Crear cifrador */
        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");

        /* Inicializar cifrador en modo DESCIFRADO */
        cifrador.init(Cipher.DECRYPT_MODE, clave);
        byte[] stringDescifrado = cifrador.doFinal(stringCifrado);

        try (FileOutputStream out = new FileOutputStream(path)) {
            out.write(stringDescifrado);
        }
    }

    private static PrivateKey getPrivateKeyFromFile(String file) throws Exception {

        //Leer datos de la clave privada del fichero
        File ficheroClavePrivada = new File(file);
        int tamanhoClavePrivada = (int) ficheroClavePrivada.length();
        byte[] bufferPriv = new byte[tamanhoClavePrivada];

        FileInputStream in = new FileInputStream(ficheroClavePrivada);
        in.read(bufferPriv, 0, tamanhoClavePrivada);
        in.close();

        //Recuperamos del formato PKCS8
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = KeyFactory.getInstance("RSA", "BC").generatePrivate(clavePrivadaSpec);

        return clavePrivada;
    }

    private static void printHashing(byte[] buffer) {
        System.out.write(buffer, 0, buffer.length);
    }

    private static PublicKey getPublicKeyFromFile(String file) throws Exception {
        File ficheroClavePublica = new File(file);
        int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
        byte[] bufferPub = new byte[tamanoFicheroClavePublica];

        FileInputStream in = new FileInputStream(ficheroClavePublica);
        in.read(bufferPub, 0, tamanoFicheroClavePublica);
        in.close();

        // Recuperar clave publica desde datos codificados en formato X509
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey clavePublica = KeyFactory.getInstance("RSA", "BC").generatePublic(clavePublicaSpec);

        return clavePublica;

    }
}
