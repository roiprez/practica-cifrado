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
    args[1] = "ExamenClaro.txt";
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

        // Descomponer en firma, clave y paquete
        if(comprobarSello(paqueteSellado, entSelladoPublica)) {
            System.out.println("\nEl sello es correcto");
            descifrarExamen(paqueteSellado, alumnoPublica, profesorPrivateKey);
        } else {
            System.out.println("\nEl sello no se ha hecho en la hora indicada por la Entidad de Sellado");
        }
    }

    private static Paquete desempaquetador(String filename) {
        return PaqueteDAO.leerPaquete(filename);
    }

    private static Boolean comprobarSello(Paquete paquete, PublicKey entSelladoPublica) throws Exception {

        byte[] selloCifrado = paquete.getBloque("Sello").getContenido();
        byte[] timeStamp = paquete.getBloque("TimeStamp").getContenido();
        byte[] datosFirma = paquete.getBloque("Firma").getContenido();
        byte[] hashFirma = funcionHashFirma(datosFirma,timeStamp);
        byte[] selloDescifrado = descifrarHashFirma(selloCifrado,entSelladoPublica);

        return MessageDigest.isEqual(selloDescifrado, hashFirma);
    }

    private static void descifrarExamen(Paquete paquete, PublicKey alumnoPublicKey, PrivateKey clavePrivProf) throws Exception {
        byte[] examenAlumnoCifrado = paquete.getBloque("Examen").getContenido();
        byte[] claveSimetrica = paquete.getBloque("Clave").getContenido();
        byte[] datosFirma = paquete.getBloque("Firma").getContenido();

        byte[] claveSimetricaDescifrada = descifrarClaveSecreta(claveSimetrica, clavePrivProf);
        //TODO: el descifrado de la firma no se usa
        byte[] firmaHash = desencriptarResumen(datosFirma, alumnoPublicKey);
        SecretKey clave = new SecretKeySpec(claveSimetricaDescifrada, 0, claveSimetricaDescifrada.length, "DES");
        descifrarSimetrico(examenAlumnoCifrado, clave, "ExamenDescifrado.txt");
        byte[] hashingExamen = funcionHashing("ExamenDescifrado.txt");

        if(MessageDigest.isEqual(hashingExamen, firmaHash)) {
            System.out.println("El examen ha sido realizado por el alumno");
        } else {
            System.out.println("El alumno no es el autor del examen");
        }
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

        byte[] hashing = messageDigest.digest(); // Completar el resumen

        //TODO- Borrar antes de enviar, solo es para traza
        System.out.println("HASH:");
        printHashing(hashing);

        return hashing;

    }

    private static byte[] desencriptarResumen(byte[] datosFirma, PublicKey alumnoPublica) throws Exception {

        byte[] resumenDescifrado;

        Cipher cifrador = Cipher.getInstance("RSA", "BC");

        cifrador.init(Cipher.DECRYPT_MODE, alumnoPublica);

        resumenDescifrado = cifrador.doFinal(datosFirma);

        //TESTING PURPOSES ONLY
        System.out.println("RESUMEN DESCIFRADO: ");
        printHashing(resumenDescifrado);

        return resumenDescifrado;

    }

    private static byte[] descifrarHashFirma(byte[] hashFirma, PublicKey entSelladoPublica)throws Exception{

        Cipher cifrador = Cipher.getInstance("RSA","BC");

        cifrador.init(Cipher.DECRYPT_MODE, entSelladoPublica);

        byte[] selloDescifrado = cifrador.doFinal(hashFirma);

        return selloDescifrado;

    }

    private static byte[] funcionHashFirma(byte[] datosFirma, byte[] TIMESTAMP) throws Exception {
        /* Crear funcion resumen */
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");

        messageDigest.update(datosFirma); // Hacer el hash de los datos de firma
        messageDigest.update(TIMESTAMP); // A�adimos el hash de timestamp

        byte[] resumenN = messageDigest.digest();

        // Mostrar resumen (no es necesario)
        System.out.println("RESUMEN HASH:");
        getBytes(resumenN);
        return resumenN;
    }

    private static void getBytes(byte[] buffer) {

        System.out.write(buffer, 0, buffer.length);
    }

    private static byte[] descifrarClaveSecreta(byte[] clave, PrivateKey ProfesorPrivateKey) throws Exception {

        byte[] bufferDescifrado;

        Cipher cifrador = Cipher.getInstance("RSA", "BC");

        cifrador.init(Cipher.DECRYPT_MODE, ProfesorPrivateKey);  // Descifra con la clave privada
        //TODO Poner aquí el return
        bufferDescifrado = cifrador.doFinal(clave);

        //TODO TESTING PURPOSES ONLY
        System.out.println("CLAVE CIFRADO: ");
        printHashing(bufferDescifrado);

        return bufferDescifrado;
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

        System.out.println("Clave Privada Profesor: " + clavePrivada);

        return clavePrivada;
    }

    //TODO Funciones auxiliares
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

        // 4.2 Recuperar clave publica desde datos codificados en formato X509
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey clavePublica = KeyFactory.getInstance("RSA", "BC").generatePublic(clavePublicaSpec);

        //TESTING PURPOSES ONLY
        System.out.println("CLAVE PUBLICA: " + clavePublica);

        return clavePublica;

    }
}
