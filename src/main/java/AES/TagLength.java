package AES;

public enum TagLength {
    TAG_128(128), TAG_120(120), TAG_112(112), TAG_104(104), TAG_96(96);

    private int length;
    TagLength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }
}
