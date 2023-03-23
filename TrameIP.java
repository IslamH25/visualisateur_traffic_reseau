import java.util.ArrayList;

import java.io.File;  // Import the File class
import java.io.IOException;  // Import the IOException class to handle errors
import java.io.FileWriter;

public class TrameIP {
    // Il s'agit de la seconde couche d'une trame

    // Attributs
    private int Version;
    private int IHL; // IP Header Length
    private String TOS; // Type Of Service
    private int TotalLength;
    private String Identification;
    private String Flags;
    private String FragmentOffset;
    private int TTL;
    private int Protocol;
    private String[] HeaderChecksum = new String[2];
    private int[] SourceAdress = new int[4];
    private int[] DestinationAdress = new int[4];
    private String[] Options;

    private ArrayList<String> data;

    private TrameTCP trameTCP;

    private File file;

    // Constructeur
    public TrameIP(ArrayList<String> data, File file) {
        this.data = data;
        this.file = file;
    }

    // Méthode d'analyse
    public void analyseIP() {
        // Version
        String t = data.get(0);
        String[] ttab = t.split("");
        t = ttab[0];
        this.Version = Integer.parseInt(t, 16);

        // HTL
        t = data.get(0);
        ttab = t.split("");
        t = ttab[1];
        this.IHL = Integer.parseInt(t, 16);

        // TOS
        this.TOS = data.get(1);

        // TotalLength
        t = data.get(2) + data.get(3);
        this.TotalLength = Integer.parseInt(t, 16);

        // Identification
        this.Identification = data.get(4) + data.get(5);

        // Flags
        this.Flags = data.get(6);

        // Fragment
        this.FragmentOffset = data.get(6) + data.get(7);

        // TTL
        this.TTL = Integer.parseInt(data.get(8), 16);

        // Protocol
        this.Protocol = Integer.parseInt(data.get(9), 16);

        // Header Checksum
        this.HeaderChecksum[0] = data.get(10);
        this.HeaderChecksum[1] = data.get(11);

        // Source Adress
        for (int i = 12; i < 16; i++) {
            this.SourceAdress[i - 12] = Integer.parseInt(data.get(i), 16);
        }

        // Destination Adress
        for (int i = 16; i < 20; i++) {
            this.DestinationAdress[i - 16] = Integer.parseInt(data.get(i), 16);
        }

        // Options
        if (IHL * 4 - 20 > 0) {
            Options = new String[IHL * 4 - 20];
            for (int i = 20; i < IHL * 4; i++) {
                Options[i - 20] = data.get(i);
            }
        }

        // Trame TCP
        ArrayList<String> newData = new ArrayList<String>();
        for (int i = IHL * 4; i < data.size(); i++) {
            newData.add(data.get(i));
        }
        trameTCP = new TrameTCP(newData, file);
        trameTCP.analyseTCP();
    }

    // Affichage
    public void affichageInfos() {

        // Trame IP
        String srcAd = "", desAd = "";
        for (int i = 0; i < 4; i++) {
            srcAd += SourceAdress[i];
            desAd += DestinationAdress[i];
            if (i != 3) {
                srcAd += ".";
                desAd += ".";
            }
        }

        try {
            FileWriter fileWriter = new FileWriter(file, true);

            fileWriter.write("Internet Protocol Version " + Version + ", Src : " + srcAd + ", Dst: " + desAd + "\n");

            // Version
            String bin = Integer.toBinaryString(Version);
            int off = 4 - bin.length();
            for (int i = 0; i < off; i++) bin = "0" + bin;
            fileWriter.write("\t" + bin + " .... = Version : " + Version + "\n");


            // IHL
            bin = Integer.toBinaryString(IHL);
            off = 4 - bin.length();
            for (int i = 0; i < off; i++) bin = "0" + bin;
            fileWriter.write("\t" + ".... " + bin + " = Header Length : " + IHL * 4 + " (" + IHL + ")\n");


            // TOS
            fileWriter.write("\t" + "Differentiated Services Field : 0x" + TOS + "\n");


            // TotalLength
            fileWriter.write("\t" + "Total Length : " + TotalLength + "\n");


            // Identification
            fileWriter.write("\t" + "Identification : 0x" + Identification + " (" + Integer.parseInt(Identification, 16) + ")\n");


            // Flags
            String first = "Flags : 0x" + Flags + "";
            String text = "";
            // Preparation
            String t = Integer.toBinaryString(Integer.parseInt(Flags, 16));
            String[] tab = t.split("");
            String[] fTab = new String[8];
            int fill = 8 - tab.length;
            for (int i = 0; i < 8; i++) {
                if (i < fill) fTab[i] = "0";
                else fTab[i] = tab[i - fill];
            }
            int v0 = Integer.parseInt(fTab[0]);
            int v1 = Integer.parseInt(fTab[1]);
            int v2 = Integer.parseInt(fTab[2]);
            // Reserved bit
            if (v0 == 0) text += "\t" + "\t0... .... = Reserved bit : Not set\n";
            else {
                text += "\t" + "\t1... .... = Reserved bit : Set\n";
                first += ", Reserved bit";
            }
            // Don't Fragment
            if (v1 == 0) text += "\t" + "\t.0.. .... = Don't fragment : Not set\n";
            else {
                text += "\t" + "\t.1.. .... = Don't fragment : Set\n";
                first += ", Don't fragment";
            }
            // More fragments
            if (v2 == 0) text += "\t" + "\t..0. .... = More fragments : Not set\n";
            else {
                text += "\t" + "\t..1. .... = More fragments : Set\n";
                first += ", More fragments";
            }
            fileWriter.write("\t" + first + "\n" + text);


            // Fragment Offset
            int vOffset = Integer.parseInt(FragmentOffset, 16);
            String binOffset = Integer.toBinaryString(vOffset);
            String[] tabOffset = binOffset.split("");
            String[] fTabOffset = new String[16];
            fill = 16 - tabOffset.length;
            for (int i = 0; i < 16; i++) {
                if (i < fill) fTabOffset[i] = "0";
                else fTabOffset[i] = tabOffset[i - fill];
            }
            String finalOffset = "";
            for (int i = 3; i < 16; i++) finalOffset += fTabOffset[i];
            vOffset = Integer.parseInt(finalOffset, 2);
            fileWriter.write("\t" + "Fragment Offset : " + vOffset + "\n");
            

            // Time To Live
            fileWriter.write("\t" + "Time to Live : " + TTL + "\n");


            // Protocol
            fileWriter.write("\t" + affichageProtocol(Protocol) + "\n");


            // Header Checksum
            fileWriter.write("\t" + "Header Checksum : 0x" + HeaderChecksum[0] + HeaderChecksum[1] + "\n");


            // Source Adress
            fileWriter.write("\t" + "Source Adress : " + srcAd + "\n");


            // Destination Adress
            fileWriter.write("\t" + "Destination Adress : " + desAd + "\n\n");

            // Options
            if (IHL * 4 - 20 > 0) fileWriter.write(ecritureOptions());

            // Fermeture de l'outil d'écriture
            fileWriter.close();

        } catch (IOException e) {
            System.out.println("Erreur lors de l'écriture");
            e.printStackTrace();
        }
        

        // Trame TCP
        trameTCP.ecritureInfos();
    }

    public String affichageProtocol(int valProtocol) {
        switch (valProtocol) {
            case 6 :
                return "Protocol : TCP (6)";

            case 1:
                return "Protocol : ICMP (1)";
        }
        return "";
    }

    public String ecritureOptions() {
        String head = "\tOptions : (" + Options.length + " bytes)";
        String body = "\n";
        int i = 0;

        while (i < Options.length) {
            int val = Integer.parseInt(Options[i], 16);

            switch (val) {
                case 134 :
                    head += ", Commercial Security";
                    int longueurC = Integer.parseInt(Options[i + 1], 16);
                    body += "\t\tIP Option - Commercial Security (" + longueurC + " bytes)\n";
                    i = i + longueurC;
                    break;

                case 7 :
                    head += ", Record Route";
                    int longueurRR = Integer.parseInt(Options[i + 1], 16);
                    int pointer = Integer.parseInt(Options[i + 2], 16);
                    body = "\t\tIP Option - Record Route (" + longueurRR + " bytes)\n";

                    for (int j = i + 3; j < i + longueurRR; j = j + 4) {
                        int valP = (j - i - 3) % 4;
                        if (valP < pointer) body += "\t\t\tRecorded Route" + Options[j] + "." + Options[j + 1] + "." + Options[j + 2] + "." + Options[j + 3] + "\n";
                        else body += "\t\t\tEmpty Route" + Options[j] + "." + Options[j + 1] + "." + Options[j + 2] + "." + Options[j + 3] + "\n";
                    }
                    i = i + longueurRR;
                    break;

                default :
                    body += "\t\tIP Option - Unknown (l'option n a pas du etre codée)\n";
                    i = Options.length;
                    break;
            }
        }

    return head + body;
        
    }

    public int getVersion() {
        return Version;
    }

    public String getTOS() {
        return TOS;
    }

    public String getIdentification() {
        return Identification;
    }

    public String getFlags() {
        return Flags;
    }

    public String getFragmentOffset() {
        return FragmentOffset;
    }

    public int getIHL() {
        return IHL;
    }

    public int getTotalLength() {
        return TotalLength;
    }

    public int getTTL() {
        return TTL;
    }

    public File getFile() {
        return file;
    }

    public TrameTCP getTrameTCP() {
        return trameTCP;
    }

    public ArrayList<String> getData() {
        return data;
    }

    public String[] getOptions() {
        return Options;
    }

    public int[] getDestinationAdress() {
        return DestinationAdress;
    }

    public int[] getSourceAdress() {
        return SourceAdress;
    }

    public String[] getHeaderChecksum() {
        return HeaderChecksum;
    }

    public int getProtocol() {
        return Protocol;
    }
}

