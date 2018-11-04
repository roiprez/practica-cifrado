import Resources.Bloque;
import Resources.Paquete;
import Resources.PaqueteDAO;
import java.time.LocalDateTime;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.*;

public class SellarExamen {

	 public static void main(String args[]) throws Exception {
	        // Comprobamos que el numero de argumentos sea correcto
	        if (args.length != 2) {
	        	System.out.println("Numero de Argumentos incorrecto");
	        	System.out.println("La entrada debe ser algo de la forma Alumno.paquete EntSellado.privada");
	            System.exit(1);
	        }
	        Security.addProvider(new BouncyCastleProvider());
	        //Leemos el  paquete del alumno
	        Paquete paquete = leerPaquete(args[0]);
	        //Extraemos la firma del paquete 
	        byte[] datosFirma = leerFirma(paquete);
	        //Construimos una estampa de la fecha y hora de sellado
	        byte[] TIMESTAMP = LocalDateTime.now().toString().getBytes();
	        //Aplicamos el hash a los datos extraidos de la firma
	        byte[] hashFirma = hashingFirma(datosFirma,TIMESTAMP);
	        //Ciframos el sello con la clave privada de la Entidad de sellado
	        PrivateKey entSelladoPrivada = getPrivateKeyFromFile(args[1]);
	        byte[] selloCifrado = cifrarHashFirma(hashFirma,entSelladoPrivada);
	        //Empaquetamos todo
	        empacador(TIMESTAMP,selloCifrado,paquete,args[0]);
	        System.out.println("Examen cifrado y Empaquetado");
	    }

	    private static void empacador(byte[] timeStamp, byte[] sello,Paquete paquete, String fichero){
	        paquete.anadirBloque("TimeStamp",timeStamp);
	        paquete.anadirBloque("Sello",sello);
	        PaqueteDAO.escribirPaquete(fichero,paquete);
	    }

	    private static Paquete leerPaquete(String nombrePaquete){
	        return PaqueteDAO.leerPaquete(nombrePaquete);
	    }

	    private static byte[] leerFirma(Paquete paquete) {
	        Bloque firma = paquete.getBloque("Firma");
	        return firma.getContenido();
	    }
	    private static byte[] hashingFirma(byte[] datosFirma, byte[] timeStamp) throws Exception {
	        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
	        messageDigest.update(datosFirma);
	        messageDigest.update(timeStamp);
	        byte[] resumenN = messageDigest.digest();
	            return resumenN;
	    }

	    private static PrivateKey getPrivateKeyFromFile(String file) throws Exception{
	        File ficheroClavePrivada = new File(file);
	        int tamanhoClavePrivada = (int) ficheroClavePrivada.length();
	        byte[] bufferPriv = new byte[tamanhoClavePrivada];
	        FileInputStream in = new FileInputStream(ficheroClavePrivada);
	        in.read(bufferPriv,0,tamanhoClavePrivada);
	        in.close();
	        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
	        PrivateKey clavePrivada = KeyFactory.getInstance("RSA","BC").generatePrivate(clavePrivadaSpec);
	        return clavePrivada;
	    }

	    private static byte[] cifrarHashFirma(byte[] hashFirma, PrivateKey selladorPrivado)throws Exception{
	        Cipher cifrador = Cipher.getInstance("RSA","BC");
	        cifrador.init(Cipher.ENCRYPT_MODE, selladorPrivado);
	        byte[] selloCifrado = cifrador.doFinal(hashFirma);
	        return selloCifrado;
	    }
  
}
