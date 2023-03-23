import java.util.ArrayList;

import java.io.File;  // Import the File class
import java.io.IOException;  // Import the IOException class to handle errors
import java.io.FileWriter;   // Import the FileWriter class

public class TrameEthernet {
    // Il s'agit de la première couche d'une trame

    // Attributs
    private String[] DestinationMAC = new String[6];
    private String[] SourceMAC = new String[6];
    private String[] Type = new String[2];

    private TrameIP trameIP;

    private ArrayList<String> data;

    // Fichier d'écriture
    private File file;

    // Constructeur
    public TrameEthernet(ArrayList<String> data, File file) {
        this.data = data;
        this.file = file;
    }

    // Méthode d'analyse
    public void analyseEthernet() {
        int i;

        for (i = 0; i < 6; i++) {
            DestinationMAC[i] = data.get(i);
        }

        for (i = 6; i < 12; i++) {
            SourceMAC[i - 6] = data.get(i);
        }

        for (i = 12; i < 14; i++) {
            Type[i - 12] = data.get(i);
        }
        ArrayList<String> newData = new ArrayList<String>();
        for (i = 14; i < data.size(); i++) {
            newData.add(data.get(i));
        }
        if (!Type[1].equals("06")){
        trameIP = new TrameIP(newData, file);
        trameIP.analyseIP();
    }}

    // Affichage des informations
    public void ecritureInfos() {
        String desMAC = "", srcMAC = "";
        for (int i = 0; i < 6; i++) {
            desMAC += DestinationMAC[i];
            srcMAC += SourceMAC[i];
            if (i != 5) {
                desMAC += ":";
                srcMAC += ":";
            }
        }

        try {
            FileWriter fileWrite = new FileWriter(file, true);

            // Trame Ethernet
            fileWrite.write("ETHERNET II, Src : (" + srcMAC + "), Dst : (" + desMAC + ")\n");

            // Destination
            fileWrite.write("\t" + "Destination : (" + desMAC + ")\n");

            // Source
            fileWrite.write("\t" + "Source : (" + srcMAC + ")\n");

            // Type
            if(Type[1].equals("00")){
            fileWrite.write("\t" + "Type : IPv4 (0x" + Type[0] + Type[1] + ")\n");}
            else {
                fileWrite.write("\t" + "Type : ARP (0x" + Type[0] + Type[1] + ")\n");}

            fileWrite.write("\n");
        
            fileWrite.close();
        } catch (IOException e) {
            System.out.println("Erreur lors de l'écriture dans le fichier");
            e.printStackTrace();
        }
        if(!Type[1].equals("06")){
        trameIP.affichageInfos();
    }}

    public String[] getDestinationMAC() {
        return DestinationMAC;
    }

    public void setDestinationMAC(String[] destinationMAC) {
        DestinationMAC = destinationMAC;
    }

    public String[] getSourceMAC() {
        return SourceMAC;
    }

    public void setSourceMAC(String[] sourceMAC) {
        SourceMAC = sourceMAC;
    }

    public String[] getType() {
        return Type;
    }

    public void setType(String[] type) {
        Type = type;
    }

    public TrameIP getTrameIP() {
        return trameIP;
    }

    public void setTrameIP(TrameIP trameIP) {
        this.trameIP = trameIP;
    }
}
