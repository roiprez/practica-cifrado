package Resources;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.security.spec.EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import org.bouncycastle.asn1.crmf.EncKeyWithID;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author ribadas
 */
public class PaqueteDAO {

    public final static String MARCA_CABECERA = "-----";
    public final static String INICIO_PAQUETE = MARCA_CABECERA + "BEGIN PACKAGE" + MARCA_CABECERA;
    public final static String FIN_PAQUETE = MARCA_CABECERA + "END PACKAGE" + MARCA_CABECERA;
    public final static String INICIO_BLOQUE = MARCA_CABECERA + "BEGIN BLOCK";
    public final static String FIN_BLOQUE = MARCA_CABECERA + "END BLOCK";
    public final static String INICIO_BLOQUE_FORMATO = INICIO_BLOQUE + " %s" + MARCA_CABECERA;
    public final static String FIN_BLOQUE_FORMATO = FIN_BLOQUE + " %s" + MARCA_CABECERA;
    public final static int ANCHO_LINEA = 65;

    public static Paquete leerPaquete(String nombreFichero) {
        Paquete result = null;
        try {
            InputStream in = new FileInputStream(nombreFichero);
            result = leerPaquete(in);
            in.close();
        } catch (FileNotFoundException ex) {
            System.err.println("No existe fichero de paquete " + nombreFichero);
            ex.printStackTrace(System.err);
            System.exit(1);
        } catch (IOException ex) {
            System.err.println("Error en fichero de paquete " + nombreFichero);
            ex.printStackTrace(System.err);
            System.exit(1);
        }
        return result;
    }

    public static void escribirPaquete(String nombreFichero, Paquete paquete) {
        try {
            PrintStream out = new PrintStream(nombreFichero);
            escribirPaquete(out, paquete);
            out.close();
        } catch (FileNotFoundException ex) {
            System.err.println("Error escribiendo fichero de paquete " + nombreFichero);
            ex.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static Paquete leerPaquete(InputStream entrada) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(entrada));
        String linea = in.readLine();

        Paquete result = new Paquete();

        while (!linea.equals(INICIO_PAQUETE)) {
            linea = in.readLine();
        }
        Bloque bloque = leerBloque(in);
        while (bloque != null) {
            result.anadirBloque(bloque.getNombre(), bloque);
            bloque = leerBloque(in);
        }

        return result;

    }

    private static void escribirPaquete(PrintStream out, Paquete paquete) {
        out.println(INICIO_PAQUETE);
        for (String nombreBloque : paquete.getNombresBloque()) {
            escribirBloque(out, nombreBloque, paquete.getBloque(nombreBloque));
        }
        out.println(FIN_PAQUETE);
    }

    private static void escribirBloque(PrintStream out, String nombreBloque, Bloque bloque) {
        if ((nombreBloque != null) && (bloque != null)) {
            out.printf(INICIO_BLOQUE_FORMATO + "\n", nombreBloque);

            byte[] contenidoBASE64 = Base64.encode(bloque.getContenido());

            int lineas = contenidoBASE64.length / ANCHO_LINEA;
            int resto = contenidoBASE64.length % ANCHO_LINEA;
            for (int i = 0; i < lineas; i++) {
                out.println(new String(contenidoBASE64, i * ANCHO_LINEA, ANCHO_LINEA));
            }
            out.println(new String(contenidoBASE64, lineas * ANCHO_LINEA, resto));

            out.printf(FIN_BLOQUE_FORMATO + "\n", nombreBloque);
        }
    }

    private static Bloque leerBloque(BufferedReader in) throws IOException {

        String linea = in.readLine();
        while ((!linea.startsWith(INICIO_BLOQUE) && (!linea.equals(FIN_PAQUETE)))) {
            linea = in.readLine();
        }
        if (linea.equals(FIN_PAQUETE)) {
            return null;  // No hay m�s bloques
        } else {
            Bloque result = new Bloque();
            result.setNombre(extraerNombreBloque(linea));
            result.setContenido(extraerContneidoBloque(in));
            return result;
        }
    }

    private static String extraerNombreBloque(String texto) {
        int inicioNombreBloque = INICIO_BLOQUE.length() + 1;
        int finNombreBloque = texto.lastIndexOf(MARCA_CABECERA);
        return texto.substring(inicioNombreBloque, finNombreBloque);
    }

    private static byte[] extraerContneidoBloque(BufferedReader in) throws IOException {
        List<String> partesBloque = new ArrayList<String>();
        int tamanoBloque = 0;

        String linea = in.readLine(); // Avanzar una linea
        while (!linea.startsWith(FIN_BLOQUE)) {
            partesBloque.add(linea);
            tamanoBloque += linea.length();
            linea = in.readLine();
        }

        byte[] result = new byte[tamanoBloque];
        int posicion = 0;
        for (String parte : partesBloque) {
            byte[] contenidoParte = parte.getBytes();
            for (byte b : contenidoParte) {
                result[posicion] = b;
                posicion++;
            }
        }
        return Base64.decode(result);
    }

    /*
     * Ejemplo de uso de las clases Paquete, Bloque y PaqueteDAO
     */
    public static void main(String[] args) {
        
        System.out.println("** Se crea un paquete y se escribe en /tmp/paquete1.bin");

        Paquete paquete = new Paquete();
        paquete.anadirBloque(new Bloque("parte1", "abcdefg".getBytes(Charset.forName("UTF-8"))));
        paquete.anadirBloque(new Bloque("parte2", "abc".getBytes(Charset.forName("UTF-8"))));
        paquete.anadirBloque(new Bloque("parte3 muy larga", "abcdefghijklmn�opqrstuvwxyz1234567890".getBytes(Charset.forName("UTF-8"))));

	
        System.out.println("** Bloques del paquete");
        for (String nombreBloque : paquete.getNombresBloque()) {
	    Bloque bloque = paquete.getBloque(nombreBloque);
            String contenidoBloque = new String(bloque.getContenido(), Charset.forName("UTF-8"));            
            System.out.println("\t"+nombreBloque+": "+ contenidoBloque.replace("\n", " "));
        }
        System.out.println("");
        
        PaqueteDAO.escribirPaquete("/tmp/paquete1.bin", paquete);

        System.out.println("** Se lee el paquete de /tmp/paquete1.bin y se vuelve a escribir en /tmp/paquete2.bin");
        Paquete paqueteLeido = PaqueteDAO.leerPaquete("/tmp/paquete1.bin");
        PaqueteDAO.escribirPaquete("/tmp/paquete2.bin", paqueteLeido);


        System.out.println();


    }
}