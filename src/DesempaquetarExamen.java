import javax.crypto.Cipher;

public class DesempaquetarExamen {
    public void main(String[] args) {
        // Leer Alumno.paquete de la entidad de sellado
        // Descomponer en firma, clave y paquete
        // Decodificar paquete de Alumno con la clave privada del profesor
        // Descifrar la clave de DES con la privada del profesor
        /*
        *  Crear cifrador
        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
        // Algoritmo DES
        // Modo : ECB (Electronic Code Book)
        // Relleno : PKCS5Padding

        // Inicializar cifrador en modo CIFRADO
        cifrador.init(Cipher.DECRYPT_MODE, clave);
        */
        // Descifrar examen con clave publica del Alumno
        // Deshacer con la firma el hash
    }
}
