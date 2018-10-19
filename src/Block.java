
public class Block {
    private String name;
    private byte[] content;

    public Block() {
        // TODO Auto-generated constructor stub
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public String toString() {
        if (content != null) {
            return this.name + ": [" + content.length + " posiciones]";
        } else {
            return this.name + ": [vacio]";
        }
    }

}
