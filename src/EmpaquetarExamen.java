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

        
         /* args[0] = "ExamenClaro";
          args[1] = "Alumno.paquete"; 
          args [2] = "Alumno.privada";
          args [3] = "Profesor.publica";*/
		
        if (args.length != 4) {
            System.out.println("Numero de Argumentos incorrecto");
            System.exit(1);
        }

         Security.addProvider(new BouncyCastleProvider());


        //RESUMEN (Acabado)
        byte[] hashingExamen = funcionHashing(args[0]);
        PrivateKey AlumnoPrivateKey = getPrivateKeyFromFile(args[2]);
        byte[] hashingExamenCifrado = EncriptarResumen(hashingExamen,AlumnoPrivateKey);

        //GENERAR CLAVE SECRETA PARA CIFRADO SIMETRICO
        SecretKey claveSimetrica = simetricKeyGenerator();

        //CIFRAR EXAMEN
        byte[] examenAlumnoCifrado = cifrarSimetrico(args[0], claveSimetrica);

        //CIFRAR CLAVE SECRETA EXAMEN
        PublicKey ProfesorPublicKey = getPublicKeyFromFile(args[3]);
        byte[] claveSimetricaCifrada = cifrarClaveSecreta(claveSimetrica,ProfesorPublicKey);

        //EMPAQUETAR
        empacador(examenAlumnoCifrado,claveSimetricaCifrada,hashingExamenCifrado,args[1]);

    }

    //MAGICPACKER!!!!
    private static void empacador (byte[] examenAlumnoCifrado, byte[] claveCifrada, byte[] resumenExamenCifrado, String filename){
        Paquete paquete = new Paquete();
        paquete.anadirBloque("Examen",examenAlumnoCifrado);
        paquete.anadirBloque("Clave",claveCifrada);
        paquete.anadirBloque("Firma",resumenExamenCifrado);

        PaqueteDAO.escribirPaquete(filename,paquete);

    }

    //Funciones de cifrado
    //Simetrico
    private static SecretKey simetricKeyGenerator() throws Exception{

        /* PASO 1: Crear e inicializar clave */

        System.out.println("1. Generar clave DES");

        KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
        generadorDES.init(56); // clave de 56 bits
        SecretKey clave = generadorDES.generateKey();

        System.out.println("CLAVE:");
        printHashing(clave.getEncoded());
        System.out.println();

        return clave;
    }

    private static byte[] cifrarSimetrico(String file, SecretKey clave)throws Exception{

		/* Crear cifrador */
        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
        // Algoritmo DES
        // Modo : ECB (Electronic Code Book)
        // Relleno : PKCS5Padding
        //

		/* Inicializar cifrador en modo CIFRADO */
        cifrador.init(Cipher.ENCRYPT_MODE, clave);


        File ficheroExamen = new File(file);
        int tamanhoExamen = (int) ficheroExamen.length();
        byte[] bufferExamen = new byte[tamanhoExamen];

        FileInputStream in = new FileInputStream(ficheroExamen);
        in.read(bufferExamen,0,tamanhoExamen);
        in.close();

        byte[] bufferCifrado = cifrador.doFinal(bufferExamen);

        //TESTING PURPOSES ONLY
        System.out.println("EXAMEN CIFRADO: ");
        printHashing(bufferCifrado);

        return bufferCifrado;

    }

    //Asimetrico
    private static byte[] cifrarClaveSecreta(SecretKey clave, PublicKey ProfesorPublicKey)throws Exception{

        byte[] bufferCifrado;

        Cipher cifrador = Cipher.getInstance("RSA", "BC");

        cifrador.init(Cipher.ENCRYPT_MODE, ProfesorPublicKey);  // Cifra con la clave publica

        bufferCifrado = cifrador.doFinal(clave.getEncoded());

        //TESTING PURPOSES ONLY
        System.out.println("CLAVE CIFRADO: ");
        printHashing(bufferCifrado);

        return bufferCifrado;
    }

    //Funciones para recuperar claves de fichero
    private static PrivateKey getPrivateKeyFromFile(String file) throws Exception{

        //Leer datos de la clave privada del fichero
        File ficheroClavePrivada = new File(file);
        int tamanhoClavePrivada = (int) ficheroClavePrivada.length();
        byte[] bufferPriv = new byte[tamanhoClavePrivada];

        FileInputStream in = new FileInputStream(ficheroClavePrivada);
        in.read(bufferPriv,0,tamanhoClavePrivada);
        in.close();

        //Recuperamos del formato PKCS8
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = KeyFactory.getInstance("RSA","BC").generatePrivate(clavePrivadaSpec);

        System.out.println("Clave Privada Alumno: "+ clavePrivada);

        return clavePrivada;
    }

    private static PublicKey getPublicKeyFromFile(String file) throws Exception{
        File ficheroClavePublica = new File(file);
        int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
        byte[] bufferPub = new byte[tamanoFicheroClavePublica];

        FileInputStream in = new FileInputStream(ficheroClavePublica);
        in.read(bufferPub, 0, tamanoFicheroClavePublica);
        in.close();

        // 4.2 Recuperar clave publica desde datos codificados en formato X509
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey clavePublica = KeyFactory.getInstance("RSA","BC").generatePublic(clavePublicaSpec);

        //TESTING PURPOSES ONLY
        System.out.println("CLAVE PUBLICA: "+clavePublica);

        return clavePublica;

    }

    //Funciones kryptograficas RESUMEN
    private static byte[] EncriptarResumen(byte[] resumen, PrivateKey alumnoPrivada)throws Exception{

        byte[] resumenCifrado;

        Cipher cifrador = Cipher.getInstance("RSA","BC");

        cifrador.init(Cipher.ENCRYPT_MODE, alumnoPrivada);

        resumenCifrado = cifrador.doFinal(resumen);

        //TESTING PURPOSES ONLY
        System.out.println("RESUMEN CIFRADO: ");
        printHashing(resumenCifrado);

        return resumenCifrado;

    }

    private static byte[] funcionHashing(String file) throws Exception{

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

    //Funciones auxiliares
    private static void printHashing(byte [] buffer) {

        System.out.write(buffer, 0, buffer.length);
    }

}
