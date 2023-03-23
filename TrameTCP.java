import java.util.ArrayList;

import java.io.File;  // Import the File class
import java.io.IOException;  // Import the IOException class to handle errors
import java.io.FileWriter;

public class TrameTCP {
    // Attributs
    private int SourcePort;
    private int DestinationPort;
    private long SequenceNumberRaw;
    private long AcknowledgmentNumberRaw;
    private int HeaderLength;
    private String Flags;
    private int Window;
    private String CheckSum;
    private int UrgentPointer;
    private String[] Options;
    private int PSH;

    private ArrayList<String> data;

    private File file;

    private TrameHTTP httpTrame = null;
    private int SYN;
    private int ACK;
    private int FIN;

    // Constructeur
    public TrameTCP(ArrayList<String> data, File file) {
        this.data = data;
        this.file = file;
    }


    // Analyse
    public void analyseTCP() {
        // Source Port 
        String sourcePortS = data.get(0) + data.get(1);
        SourcePort = Integer.parseInt(sourcePortS, 16);

        // Destination Port
        String destinationPortS = data.get(2) + data.get(3);
        DestinationPort = Integer.parseInt(destinationPortS, 16);

        // Sequence Number Raw
        String UpperSNR = data.get(4) + data.get(5);
        String LowerSNR = data.get(6) + data.get(7);
        SequenceNumberRaw = Long.parseLong(UpperSNR + LowerSNR, 16);

        // Ack. Number Raw
        String UpperANR = data.get(8) + data.get(9);
        String LowerANR = data.get(10) + data.get(11);
        AcknowledgmentNumberRaw = Long.parseLong(UpperANR + LowerANR, 16);

        // Header Length
        HeaderLength = Integer.parseInt(data.get(12).split("")[0], 16);

        // Flags
        String FLGS = data.get(12) + data.get(13);
        String[] FLGSTab = FLGS.split("");
        Flags = FLGSTab[1] + FLGSTab[2] + FLGSTab[3];
        
        // Window
        Window = Integer.parseInt(data.get(14) + data.get(15), 16);

        // CheckSum
        CheckSum = data.get(16) + data.get(17);

        // Urgent Pointer
        UrgentPointer = Integer.parseInt(data.get(18) + data.get(19), 16);


        // Options
        if (HeaderLength*4>20){
        Options = new String[(HeaderLength * 4) - 20];
        for (int i = 20; i < HeaderLength * 4; i++) {
            Options[i - 20] = data.get(i);
        }}
        // Possible trame HTTP
        if (((HeaderLength * 4) != data.size()&& !data.get(HeaderLength*4).equals("00"))) {
            ArrayList<String> newData = new ArrayList<String>();

            for (int i = HeaderLength * 4; i < data.size(); i++) newData.add(data.get(i));
            httpTrame = new TrameHTTP(newData, file);
        }else {
            httpTrame=null;
        }

    }

    // Affichage
    public void ecritureInfos() {
        try {
            FileWriter fileWriter = new FileWriter(file, true);

            // Trame TCP
            fileWriter.write("Transmission Control Protocol, Src Port : " + SourcePort + ", Dst Port = " + DestinationPort + "\n");

            // Source Port
            fileWriter.write("\t" + "Source Port : " + SourcePort + "\n");

            // Destination Port
            fileWriter.write("\t" + "Destination Port : " + DestinationPort + "\n");

            // Seq. Number Raw
            fileWriter.write("\t" + "Sequence Number (raw) : " + SequenceNumberRaw + "\n");

            // Ack. Number Raw
            fileWriter.write("\t" + "Acknowledgment Number (raw) : " + AcknowledgmentNumberRaw + "\n");

            // Header Length
            String valueBin = Integer.toBinaryString(HeaderLength);
            int o = 4 - valueBin.length();
            for (int i = 0; i < o; i++) valueBin = "0" + valueBin;
            fileWriter.write("\t" + valueBin + " .... = Header Length : " + HeaderLength * 4 + " bytes (" + HeaderLength + ")\n");

            // Flags
            fileWriter.write("\t" + affichageFlags(Flags));

            // Window
            fileWriter.write("\t" + "Window : " + Window + "\n");

            // Checksum
            fileWriter.write("\t" + "Checksum : 0x" + CheckSum + "\n");

            // UrgentPointer
            fileWriter.write("\t" + "Urgent Pointer : " + UrgentPointer + "\n");

            // Options
            if (HeaderLength*4>20)fileWriter.write(afficheOptions(Options));

            // Fermeture de l'outil
            fileWriter.close();
            
        }
        catch (IOException e) {
            System.out.println("Erreur lors de l'écriture dans le fichier.");
            e.printStackTrace();
        }

        // HTTP
        if (httpTrame != null) {
            httpTrame.ecritureInfos();
        }
    }
    
    // Méthodes
    public String affichageFlags(String fl) {
        // Preparation
        int flagValue = Integer.parseInt(fl, 16);
        String[] tempTab = Integer.toBinaryString(flagValue).split("");
        String[] flagTab = new String[12];
        int o = 12 - tempTab.length;
        for (int i = 0; i < 12; i++) {
            if (i < o) flagTab[i] = "0";
            else flagTab[i] = tempTab[i - o];
        }

        // Texte
        String head = "Flags : 0x" + fl + " ";
        String body = "";

        // Reserved
        int reserved = Integer.parseInt(flagTab[0] + flagTab[1] + flagTab[2], 2);
        if (reserved == 0) body += "\t" + "\t000. .... .... = Reserved : Not set\n";
        else body += "\t" + "\t" + flagTab[0] + flagTab[1] + flagTab[2] + ". .... .... = Reserved : Set\n";

        // Nonce
        int nonce = Integer.parseInt(flagTab[3], 2);
        if (nonce == 0) body += "\t" + "\t...0 .... .... = Nonce : Not set\n";
        else body += "\t" + "\t...1 .... .... = Nonce : Set\n";

        // Congestion
        int cong = Integer.parseInt(flagTab[4], 2);
        if (cong == 0) body += "\t" + "\t.... 0... .... = Congestion Window Reduced (CWR) : Not set\n";
        else body += "\t" + "\t.... 1... .... = Congestion Window Reduced (CWR) : Set\n";

        // ECN
        int ecn = Integer.parseInt(flagTab[5], 2);
        if (ecn == 0) body += "\t" + "\t.... .0.. .... = ECN-Echo : Not set\n";
        else body += "\t" + "\t.... .1.. .... = ECN-Echo : Set\n";

        // Urgent
        int urg = Integer.parseInt(flagTab[6], 2);
        if (urg == 0) body += "\t" + "\t.... ..0. .... = Urgent : Not set\n";
        else body += "\t" + "\t.... ..1. .... = Urgent : Set\n";

        // Ack.
        int ack = Integer.parseInt(flagTab[7], 2);
        if (ack == 0) body += "\t" + "\t.... ...0 .... = Acknowledgment : Not set\n";
        else {
            head += "(ACK) ";
            body += "\t" + "\t.... ...1 .... = Acknowledgment : Set\n";
        }
        ACK=ack;

        // Push
        int push = Integer.parseInt(flagTab[8], 2);
        if (push == 0) body += "\t" + "\t.... .... 0... = Push : Not set\n";
        else {
            head += "(PSH) ";
            body += "\t" + "\t.... .... 1... = Push : Set\n";
        }
        PSH=push;

        // Reset
        int reset = Integer.parseInt(flagTab[9], 2);
        if (reset == 0) body += "\t" + "\t.... .... .0.. = Reset : Not set\n";
        else {
            head += "(RST) ";
            body += "\t" + "\t.... .... .1.. = Reset : Set\n";
        }

        // Syn
        int syn = Integer.parseInt(flagTab[10], 2);
        if (syn == 0) body += "\t" + "\t.... .... ..0. = Syn : Not set\n";
        else {
            head += "(SYN) ";
            body += "\t" + "\t.... .... ..1. = Syn : Set\n";
        }
        SYN=syn;

        // Fin
        int fin = Integer.parseInt(flagTab[11], 2);
        if (fin == 0) body += "\t" + "\t.... .... ...0 = Fin : Not set\n";
        else {
            head += "(FIN) ";
            body += "\t" + "\t.... .... ...1 = Fin : Set\n";
        }
        FIN=fin;

        // Affichage
        head += "\n";
        return head + body;
    }

    public String afficheOptions(String[] tabOptions) {
        String head = "\tOptions : (" + tabOptions.length + " bytes)";
        String body = "\n";

        int i = 0;
        while (i < tabOptions.length) {
            String opt = tabOptions[i];
            int val = Integer.parseInt(opt, 16);

            switch (val) {
                // End of Option
                case 0 :
                    i = tabOptions.length;
                    break;

                // No Operation
                case 1 :
                    head += ", No-Operation (NOP)";
                    body += "\t\tTCP Option - No-Operation (NOP)\n";
                    i++;
                    break;

                // Maximum Segment Size
                case 2 :
                    int length = Integer.parseInt(tabOptions[i + 2] + tabOptions[i + 3], 16);
                    head += ", Maximum Segment Size";
                    body += "\t\tTCP Option - Maximum segment size : " + length + " bytes\n";
                    i = i + 4;
                    break;

                // Window scale
                case 3 :
                    int power = (int)Math.pow(2, Integer.parseInt(tabOptions[i + 2], 16));
                    head += ", Window Scale";
                    body += "\t\tTCP Option - Window scale : " + Integer.parseInt(tabOptions[i + 2], 16) + " (multiply by " + power + ")\n";
                    i = i + 3;
                    break;

                // SACK permitted
                case 4 :
                    head += ", SACK permitted";
                    body += "\t\tTCP Option - SACK permitted\n";
                    i = i + 2;
                    break;

                // Timestamps
                case 8 :
                    int longueur = Integer.parseInt(tabOptions[i + 1], 16);
                    String value = "";
                    for (int j = i + 2; j < i + longueur - 4; j++) {
                        value += tabOptions[j];
                    }
                    long fVal = Long.parseLong(value, 16);

                    value = "";
                    for (int j = i + 6; j < i + longueur; j++) {
                        value += tabOptions[j];
                    }
                    long sVal = Long.parseLong(value, 16);

                    head += ", Timestamps";
                    body += "\t\tTCP Option - Timestamps : TSVal " + fVal + ", TSecr " + sVal + "\n";
                    i = i + 10;
                    break;

                // Autre
                default :
                    body += "\t\tTCP Option - Unknown (l'option n'a pas du etre codée)\n";
                    i = tabOptions.length;
                    break;

            }

        }

        return head + body;
    }

    public int getSourcePort() {
        return SourcePort;
    }

    public TrameHTTP getHttpTrame() {
        return httpTrame;
    }

    public File getFile() {
        return file;
    }

    public ArrayList<String> getData() {
        return data;
    }

    public String[] getOptions() {
        return Options;
    }

    public int getUrgentPointer() {
        return UrgentPointer;
    }

    public String getCheckSum() {
        return CheckSum;
    }

    public int getWindow() {
        return Window;
    }

    public String getFlags() {
        return Flags;
    }

    public int getHeaderLength() {
        return HeaderLength;
    }

    public long getAcknowledgmentNumberRaw() {
        return AcknowledgmentNumberRaw;
    }

    public long getSequenceNumberRaw() {
        return SequenceNumberRaw;
    }

    public int getDestinationPort() {
        return DestinationPort;
    }

    public int getSYN() {
        return SYN;
    }

    public int getFIN() {
        return FIN;
    }

    public int getACK() {
        return ACK;
    }

    public int getPSH() {
        return PSH;
    }
}
