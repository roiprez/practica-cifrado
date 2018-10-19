import java.security.Timestamp;

public class SealedDocument {
    private Timestamp sealTime;
    private String document;

    public SealedDocument(Timestamp sealTime, String document) {
        this.sealTime = sealTime;
        this.document = document;
    }

    public Timestamp getSealTime() {
        return sealTime;
    }

    public String getDocument() {
        return document;
    }
}