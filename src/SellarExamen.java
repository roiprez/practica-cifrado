import java.io.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import Resources.Bloque;
import Resources.Paquete;
import Resources.PaqueteDAO;

import java.security.*;
import javax.crypto.*;
public class SellarExamen {

	 public static void main(String args[]) throws Exception {

	        /*
	        *  args[0] = Alumno.paquete
	        *  args[1] = EntSellado.privada
	        * */

	        // Comprobar argumentos
	        if (args.length != 2) {
	        	System.out.println("Numero de Argumentos incorrecto");
	            System.exit(1);
	        }

	        Security.addProvider(new BouncyCastleProvider());

	        //Leer paquete
	        Paquete paquete = leerPaquete(args[0]);

	        //Recuperar firma
	        byte[] datosFirma = leerDatosFirma(paquete);

	        //TIMESTAMP
	        //byte[] TIMESTAMP = new TimestampToken(hashFirma).getHashedMessage();
	        byte[] TIMESTAMP = LocalDateTime.now().toString().getBytes();

	        //Hash_Firma
	        byte[] hashFirma = funcionHashFirma(datosFirma,TIMESTAMP);

	        //CIFRAR HASH
	        PrivateKey entSelladoPrivada = getPrivateKeyFromFile(args[1]);
	        byte[] selloCifrado = cifrarHashFirma(hashFirma,entSelladoPrivada);

	        //Anadir bloque timestamp, Anadir bloque HASH cifrado (SELLO), Guardar paquete
	        magicPackerLite(paquete,TIMESTAMP,selloCifrado,args[0]);

	    }

	    private static void magicPackerLite(Paquete paquete, byte[] TimeStamp, byte[] selloCifrado, String filename){
	        paquete.anadirBloque("TimeStamp",TimeStamp);
	        paquete.anadirBloque("Sello",selloCifrado);

	        PaqueteDAO.escribirPaquete(filename,paquete);
	    }

	    private static Paquete leerPaquete(String nombrePaquete){
	        return PaqueteDAO.leerPaquete(nombrePaquete);
	    }

	    private static byte[] leerDatosFirma(Paquete paquete) {

	        Bloque firma = paquete.getBloque("Firma");
	        return firma.getContenido();

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

	        System.out.println("Clave Privada Sellador: "+ clavePrivada);

	        return clavePrivada;
	    }

	    private static byte[] cifrarHashFirma(byte[] hashFirma, PrivateKey selladorPrivado)throws Exception{

	        Cipher cifrador = Cipher.getInstance("RSA","BC");

	        cifrador.init(Cipher.ENCRYPT_MODE, selladorPrivado);

	        byte[] selloCifrado = cifrador.doFinal(hashFirma);

	        //TODO- Borrar antes de enviar, solo es para traza
	        System.out.println("SELLO: ");
	        getBytes(selloCifrado);

	        return selloCifrado;

	    }

	    private static void getBytes(byte[] buffer) {

	        System.out.write(buffer, 0, buffer.length);
	    }
  
}
