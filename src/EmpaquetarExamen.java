import org.bouncycastle.jce.provider.BouncyCastleProvider;

import Resources.Paquete;
import Resources.PaqueteDAO;

import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EmpaquetarExamen {

    public static void main(String[] args) throws Exception {

    	// Comprobamos que el numero de argumentos sea correcto
        if (args.length != 4) {
            System.out.println("Numero de Argumentos incorrecto");
            System.out.println("La entrada debe ser algo de la forma ExamenClaro.txt Alumno.paquete Alumno.privada Profesor.publica");
            System.exit(1);
        }
        Security.addProvider(new BouncyCastleProvider());
        //Generamos la clave secreta para el cifrado simetrico
        SecretKey claveSimetrica = simetricKeyGenerator();
        //Ciframos la clave secreta del examen para su posterior empaquetado
        PublicKey ProfesorPublicKey = getPublicKeyFromFile(args[3]);
        byte[] claveSimetricaCifrada = encriptarClaveSecreta(claveSimetrica, ProfesorPublicKey);
        //Aplicamos hash para verificar que la informacion es la misma en los extremos
        byte[] hashingExamen = hashing(args[0]);
        PrivateKey AlumnoPrivateKey = getPrivateKeyFromFile(args[2]);
        byte[] hashingExamenCifrado = encriptarHashing(hashingExamen, AlumnoPrivateKey);
        //Ciframos el examen antes de empaquetarlo
        byte[] examenAlumnoCifrado = cifradoSimetrico(args[0], claveSimetrica);
        //Empaquetamos todo
        empacador(claveSimetricaCifrada, hashingExamenCifrado,examenAlumnoCifrado, args[1]);
        System.out.println("Examen cifrado y Empaquetado");

    }


    private static void empacador(byte[] claveCifrada, byte[] hashExamenCifrado,byte[] examenCifrado, String ficheroSalida) {
        Paquete paquete = new Paquete();
        paquete.anadirBloque("Clave", claveCifrada);
        paquete.anadirBloque("Firma", hashExamenCifrado);
        paquete.anadirBloque("Examen", examenCifrado);
        PaqueteDAO.escribirPaquete(ficheroSalida, paquete);
    }

  //Funciones de Cifrado
    private static SecretKey simetricKeyGenerator() throws Exception {
        KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
        generadorDES.init(56);
        SecretKey clave = generadorDES.generateKey();
        return clave;
    }
    private static byte[] cifradoSimetrico(String fichero, SecretKey clave) throws Exception {
        // Creamos un cifrador simetrico
        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
        // Lo ponemos en modo cifrar
        cifrador.init(Cipher.ENCRYPT_MODE, clave);
        File ficheroExamen = new File(fichero);
        int longitud = (int) ficheroExamen.length();
        byte[] examenClaro = new byte[longitud];
        FileInputStream entrada = new FileInputStream(ficheroExamen);
        entrada.read(examenClaro, 0, longitud);
        entrada.close();
        byte[] examenCifrado = cifrador.doFinal(examenClaro);
        return examenCifrado;
    }

    
    private static byte[] encriptarClaveSecreta(SecretKey clave, PublicKey ProfesorPublicKey) throws Exception {
        Cipher cifrador = Cipher.getInstance("RSA", "BC");
        cifrador.init(Cipher.ENCRYPT_MODE, ProfesorPublicKey);  // Ciframos con la clave publica del profesor para garatizar que solo el pude ver la clave aleatoria
        byte[] claveCifrada = cifrador.doFinal(clave.getEncoded());
        return claveCifrada;
    }

    private static byte[] encriptarHashing(byte[] resumen, PrivateKey alumnoPrivada) throws Exception {
        byte[] resumenCifrado;
        Cipher theCipher = Cipher.getInstance("RSA", "BC");
        theCipher.init(Cipher.ENCRYPT_MODE, alumnoPrivada);
        resumenCifrado = theCipher.doFinal(resumen);
        return resumenCifrado;

    }
    
    //Funciones de extraccion de claves de ficheros
    private static PrivateKey getPrivateKeyFromFile(String file) throws Exception {
        File ficheroClavePrivada = new File(file);
        int longitudClavePrivada = (int) ficheroClavePrivada.length();
        byte[] bufferPriv = new byte[longitudClavePrivada];
        FileInputStream entrada = new FileInputStream(ficheroClavePrivada);
        entrada.read(bufferPriv, 0, longitudClavePrivada);
        entrada.close();
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = KeyFactory.getInstance("RSA", "BC").generatePrivate(clavePrivadaSpec);
        return clavePrivada;
    }

    private static PublicKey getPublicKeyFromFile(String file) throws Exception {
        File ficheroClavePublica = new File(file);
        int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
        byte[] bufferPub = new byte[tamanoFicheroClavePublica];
        FileInputStream entrada = new FileInputStream(ficheroClavePublica);
        entrada.read(bufferPub, 0, tamanoFicheroClavePublica);
        entrada.close();
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey clavePublica = KeyFactory.getInstance("RSA", "BC").generatePublic(clavePublicaSpec);
        return clavePublica;
    }

    //Funciones auxiliares
    private static byte[] hashing(String file) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] buffer = new byte[1000];
        FileInputStream entrada = new FileInputStream(file);
        int procesados = entrada.read(buffer, 0, 1000);
        while (procesados != -1) {
            messageDigest.update(buffer, 0, procesados);
            procesados = entrada.read(buffer, 0, 1000);
        }
        entrada.close();
        byte[] hashing = messageDigest.digest();
        return hashing;
    }
}
