import java.io.*;
import java.util.ArrayList;

public class Trame {
    // Attributs
    private static int globalID = 1;

    private int ID;
    private ArrayList<String> data;
    private int length;
    private TrameEthernet trameEthernet;

    private File file;

    // Constructeur
    public Trame() throws FileNotFoundException {
        ID = globalID;
        globalID++;

        data = new ArrayList<String>();

        try {
            file = new File("Analyse_Trame.txt");
            if (file.createNewFile()) {
                System.out.println("Le fichier (Analyse_Trame.txt) a correctement été crée.\n");
            } else {
                System.out.println("Le fichier (Analyse_Trame.txt) a déjà été crée. Nous allons donc le vider.\n");
                file.delete();

                file = new File("Analyse_Trame.txt");
            }
        } catch (IOException e) {
            System.out.println("Probleme lors de la création du fichier.");
        }

    }

    // Modificateurs
    public void modifyTrameBytes(ArrayList<String> newArray) {
        data.addAll(newArray);
    }

    public void addTrameBytes(ArrayList<String> newList) { // Ajoute une nouvelle chaine d'octets à la chaine deja existante et met à jour la taille de la chaine
        for (String s : newList) {
            data.add(s);
        }
        length = data.size();
    }

    // Accesseurs
    public int getLength() { return this.length; }

    public TrameEthernet getTrameEthernet() { return trameEthernet; }

    public int getID() { return ID; }

    // Méthodes
    public String toString(int valParLigne) {
        String text = "";

        for (int i = 0; i < length; i++) {
            text += data.get(i);
            if ((i != 0) && ((i + 1) % valParLigne == 0)) text += "\n";
            else text += " ";
        }

        return text;
    }

    public void analyseTrame() {
        System.out.println("On commence l'analyse de la trame " + ID + " ...\n");
        trameEthernet = new TrameEthernet(data, file);
        trameEthernet.analyseEthernet();
    }

    // Affichage
    public void ecritureInfos() {
        System.out.println("Ecriture des informations à propos de la trame n." + ID + "\n");

        try {
            FileWriter fileWriter;

            if (ID == 0) fileWriter = new FileWriter(file);
            else fileWriter = new FileWriter(file, true);

            fileWriter.write("Informations à propos de la trame n." + ID + "\n\n");

            fileWriter.close();
        } catch (IOException e) {
            System.out.println("Erreur lors de l'écriture");
            e.printStackTrace();
        }
    
        trameEthernet.ecritureInfos();

        try {
            FileWriter fileWriter = new FileWriter(file, true);

            if (ID != globalID - 1) fileWriter.write("\n####################################################################################################\n\n");

            fileWriter.close();
        } catch (IOException e) {
            System.out.println("Erreur lors de l'écriture dans le fichier");
            e.printStackTrace();
        }
    }
   public void flowGraph(PrintStream printStream){
           TrameTCP tTCP=trameEthernet.getTrameIP().getTrameTCP();
           String srcAd1=""; String destAd1="";
           for (int j = 0; j < 4; j++) {
               srcAd1 += String.valueOf(trameEthernet.getTrameIP().getSourceAdress()[j]);
               destAd1+= String.valueOf(trameEthernet.getTrameIP().getDestinationAdress()[j]);
               if (j != 3) {
                   srcAd1 += ".";
                   destAd1+= ".";
               }}
           if(tTCP.getSourcePort()>1024) {
              System.out.println("       " + srcAd1 + "                                                                                          " + destAd1);

               printStream.println("       " + srcAd1 + "                                                                                          " + destAd1);
           }else{
               System.out.println("       " + destAd1 + "                                                                                          " + srcAd1);

               printStream.println("       " + destAd1 + "                                                                                          " + srcAd1);
           }
           if (tTCP.getHttpTrame()==null){
               //SYN
               if(tTCP.getSYN()==1&&tTCP.getACK()==0&&tTCP.getFIN()==0){
                   System.out.println("          |"+tTCP.getSourcePort()+"->"+tTCP.getDestinationPort()+"[SYN]Seq="+tTCP.getSequenceNumberRaw()+" Win="+tTCP.getWindow()+" Lenght="+tTCP.getHeaderLength()+" Checksum="+tTCP.getCheckSum()+"                                              |");

                   printStream.println("          |"+tTCP.getSourcePort()+"->"+tTCP.getDestinationPort()+"[SYN]Seq="+tTCP.getSequenceNumberRaw()+" Win="+tTCP.getWindow()+" Lenght="+tTCP.getHeaderLength()+" Checksum="+tTCP.getCheckSum()+"                                              |");
               }
               //SYN,ACK
               if(tTCP.getSYN()==1&&tTCP.getACK()==1&&tTCP.getFIN()==0){
                   System.out.println("          |"+tTCP.getSourcePort()+"->"+tTCP.getDestinationPort()+"[SYN,ACK]Seq="+tTCP.getSequenceNumberRaw()+" Ack="+tTCP.getAcknowledgmentNumberRaw()+" Win="+tTCP.getWindow()+" Lenght="+tTCP.getHeaderLength()+" Checksum="+tTCP.getCheckSum()+"                            |");

                   printStream.println("          |"+tTCP.getSourcePort()+"->"+tTCP.getDestinationPort()+"[SYN,ACK]Seq="+tTCP.getSequenceNumberRaw()+" Ack="+tTCP.getAcknowledgmentNumberRaw()+" Win="+tTCP.getWindow()+" Lenght="+tTCP.getHeaderLength()+" Checksum="+tTCP.getCheckSum()+"                            |");
               }
               //ACK
               if(tTCP.getSYN()==0&&tTCP.getACK()==1&&tTCP.getFIN()==0){
                   System.out.println("          |"+tTCP.getSourcePort()+"->"+tTCP.getDestinationPort()+"[ACK]Seq="+tTCP.getSequenceNumberRaw()+" Ack="+tTCP.getAcknowledgmentNumberRaw()+" Win="+tTCP.getWindow()+" Lenght="+tTCP.getHeaderLength()+" Checksum="+tTCP.getCheckSum()+"                                |");

                   printStream.println("          |"+tTCP.getSourcePort()+"->"+tTCP.getDestinationPort()+"[ACK]Seq="+tTCP.getSequenceNumberRaw()+" Ack="+tTCP.getAcknowledgmentNumberRaw()+" Win="+tTCP.getWindow()+" Lenght="+tTCP.getHeaderLength()+" Checksum="+tTCP.getCheckSum()+"                                |");
               }
               //FIN,ACK
               if(tTCP.getSYN()==0&&tTCP.getACK()==1&&tTCP.getFIN()==1){
                   System.out.println("          |"+tTCP.getSourcePort()+"->"+tTCP.getDestinationPort()+"[FIN,ACK]Seq="+tTCP.getSequenceNumberRaw()+" Ack="+tTCP.getAcknowledgmentNumberRaw()+" Win="+tTCP.getWindow()+" Lenght="+tTCP.getHeaderLength()+" Checksum="+tTCP.getCheckSum()+"                            |");

                   printStream.println("          |"+tTCP.getSourcePort()+"->"+tTCP.getDestinationPort()+"[FIN,ACK]Seq="+tTCP.getSequenceNumberRaw()+" Ack="+tTCP.getAcknowledgmentNumberRaw()+" Win="+tTCP.getWindow()+" Lenght="+tTCP.getHeaderLength()+" Checksum="+tTCP.getCheckSum()+"                            |");
               }}else{
                System.out.println("          |"+tTCP.getHttpTrame().getRequete());

               printStream.println("          |"+tTCP.getHttpTrame().getRequete());

           }
           if (tTCP.getSourcePort()>1024){
               System.out.println("     "+tTCP.getSourcePort()+"------------------------------------------------------------------------------------------------------------>"+tTCP.getDestinationPort());
               printStream.println("     "+tTCP.getSourcePort()+"------------------------------------------------------------------------------------------------------------>"+tTCP.getDestinationPort());
               System.out.println("\n");

               printStream.println("\n");}else{
               System.out.println("     "+tTCP.getDestinationPort()+"<------------------------------------------------------------------------------------------------------------"+tTCP.getSourcePort());

               printStream.println("     "+tTCP.getDestinationPort()+"<------------------------------------------------------------------------------------------------------------"+tTCP.getSourcePort());
               System.out.println("\n");
               printStream.println("\n");

           }
   }

}
